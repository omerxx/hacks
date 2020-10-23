package main

import (
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

/*
 * AWS IAM scanner tool
 * Iterates through provided -profiles (or uses "default" local profile)
 * It will scan users access keys and passwords and report keys older than -age (defaults to 365 days)
 * If set to -active it will perform actions according to the rules listed below
 *
 * Rules:
 * [*] If a user on an account never used login - disable his console access
 * [*] If a key has never been used - remove it
 * [*] If a key hasn’t been used in over a year - remove it
 * [not implemented] If a user has never accessed the console and hasn’t got keys (or has unused keys), delete the user
 */
var allowedCredentialsAge float64
var activeMode *bool
var focusMode *bool
var prefix string
var now = time.Now()
var log = logrus.New()

func main() {
	var profilesFlag = flag.String("profiles", "default", "An AWS CLI profile name, or comma-separated list for multiple")
	var ageFlag = flag.Float64("age", 365, "Age in DAYS beyond keys and activity will be addressed")
	activeMode = flag.Bool("active", false, "Active mode - deactivates users and keys according to rules")
	focusMode = flag.Bool("focus", false, "Focus mode - only shows actionable items")
	flag.Parse()

	logFormat := new(logrus.TextFormatter)
	logFormat.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(logFormat)
	logFormat.FullTimestamp = true

	var profiles = strings.Split(*profilesFlag, ",")
	allowedCredentialsAge = *ageFlag
	for _, profile := range profiles {
		log.Infof("\n-----------------\nScanning account %s\n-----------------", profile)
		checkAccountCredentials(profile)
	}
}

func checkAccountCredentials(profile string) {
	session, _ := session.NewSessionWithOptions(session.Options{
		Profile: profile,
	})
	users, err := listUsers(session)
	if err != nil {
		logrus.Error(err)
	}
	checkUsersCredentialsAge(session, users, profile)
}

func listUsers(session *session.Session) ([]*iam.User, error) {
	svc := iam.New(session)
	input := &iam.ListUsersInput{}
	result, err := svc.ListUsers(input)
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

func checkUsersCredentialsAge(session *session.Session, users []*iam.User, profile string) {
	for _, user := range users {
		prefix = fmt.Sprintf("%s | %s: ", profile, *user.UserName)
		listUserRoles(session, user)
		checkUsersConsoleLoginAge(session, user)
		checkUsersAccessKeysAge(session, user)
		logrus.Infof("\n")
	}
}

func listUserRoles(session *session.Session, user *iam.User) {
	// list attached user policies
	svc := iam.New(session)
	input := &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(*user.UserName),
	}
	policies, err := svc.ListAttachedUserPolicies(input)
	if err != nil {
		logrus.Error(err)
	}
	logrus.Infof("---------%s---------", *user.UserName)
	for _, policy := range policies.AttachedPolicies {
		if strings.Contains(*policy.PolicyName, "FullAccess") || strings.Contains(*policy.PolicyName, "Admin") || strings.Contains(*policy.PolicyName, "admin") {
			log.WithFields(logrus.Fields{"Issue": "Full Access permissions"}).Errorf("\t%s", *policy.PolicyName)
		} else if *focusMode == false {
			log.Infof("\t%s", *policy.PolicyName)
		}
	}
}

func checkUsersConsoleLoginAge(session *session.Session, user *iam.User) {
	if hasLoginProfile(session, user) == true {
		if user.PasswordLastUsed == nil {
			// log.Warn(fmt.Sprintf("%s Password never used, but user has a login profile", prefix))
			log.WithFields(
				logrus.Fields{"Issue": "password never used, but user has a login profile"},
			).Warn()
			if *activeMode {
				log.Warn(fmt.Sprintf("%s Disabling console access", prefix))
				deleteUserLoginProfile(session, *user.UserName)
			}
		} else if olderThanAge(*user.PasswordLastUsed) {
			log.WithFields(
				logrus.Fields{
					"Optional": "Remove console profile",
				}).Info(fmt.Sprintf(
				// "%s Password last used %d days ago", prefix, int(now.Sub(*user.PasswordLastUsed).Hours()/24),
				"\tPassword last used %d days ago", int(now.Sub(*user.PasswordLastUsed).Hours()/24),
			))
		}
	}
}

func hasLoginProfile(session *session.Session, user *iam.User) bool {
	svc := iam.New(session)
	input := &iam.GetLoginProfileInput{
		UserName: aws.String(*user.UserName),
	}

	_, err := svc.GetLoginProfile(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Debugf("No login profile for %s", *user.UserName)
				return false
			default:
				log.Error(iam.ErrCodeServiceFailureException, aerr.Error())
			}
		} else {
			log.Error(iam.ErrCodeServiceFailureException, aerr.Error())
		}
	}
	return true
}

func deleteUserLoginProfile(session *session.Session, username string) {
	svc := iam.New(session)
	input := &iam.DeleteLoginProfileInput{
		UserName: aws.String(username),
	}
	_, err := svc.DeleteLoginProfile(input)
	if err != nil {
		log.Error(err)
	}
}

func checkUsersAccessKeysAge(session *session.Session, user *iam.User) {
	userAccessKeys, err := listUserAccessKeys(session, *user.UserName)
	if err != nil {
		fmt.Println(err)
	}
	for _, key := range userAccessKeys {
		lastUsed, err := getAccessKeyLastUsed(session, *key.AccessKeyId)
		if err != nil {
			fmt.Println(err)
		}
		if lastUsed == nil {
			log.Warnf("\tAccess key never used [%s]", *key.AccessKeyId)
			if *activeMode {
				log.Warn("Removing access key")
				deleteAccessKeys(session, *key.AccessKeyId)
			}
		} else if olderThanAge(*lastUsed) {
			log.WithFields(
				logrus.Fields{
					"Optional": "Rotate key",
				}).Info(fmt.Sprintf(
				"\tKey %s last used %d days ago", *key.AccessKeyId, int(now.Sub(*lastUsed).Hours()/24),
			))
			if *activeMode {
				log.Warn(fmt.Sprintf("%s Removing access key", prefix))
				deleteAccessKeys(session, *key.AccessKeyId)
			}
		}
	}
}

func deleteAccessKeys(session *session.Session, accessKeyID string) {
	svc := iam.New(session)
	input := &iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(accessKeyID),
	}
	_, err := svc.DeleteAccessKey(input)
	if err != nil {
		log.Error(err)
	}
}

func olderThanAge(input time.Time) bool {
	return now.Sub(input).Hours()/24 > allowedCredentialsAge
}

func listUserAccessKeys(session *session.Session, username string) ([]*iam.AccessKeyMetadata, error) {
	svc := iam.New(session)
	input := &iam.ListAccessKeysInput{
		UserName: aws.String(username),
	}
	result, err := svc.ListAccessKeys(input)
	if err != nil {
		return nil, err
	}
	return result.AccessKeyMetadata, nil
}

func getAccessKeyLastUsed(session *session.Session, accessKeyID string) (*time.Time, error) {
	svc := iam.New(session)
	input := &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: aws.String(accessKeyID),
	}
	result, err := svc.GetAccessKeyLastUsed(input)
	if err != nil {
		return nil, err
	}
	return result.AccessKeyLastUsed.LastUsedDate, nil
}
