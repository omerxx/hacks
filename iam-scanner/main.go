package main

import (
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	log "github.com/sirupsen/logrus"
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
var prefix string
var now = time.Now()

func main() {
	var profilesFlag = flag.String("profiles", "default", "An AWS CLI profile name, or comma-separated list for multiple")
	var ageFlag = flag.Float64("age", 365, "Age in DAYS beyond keys and activity will be addressed")
	activeMode = flag.Bool("active", false, "Active mode - deactivates users and keys according to rules")
	flag.Parse()

	var profiles = strings.Split(*profilesFlag, ",")
	allowedCredentialsAge = *ageFlag
	for _, profile := range profiles {
		checkAccountCredentials(profile)
	}
}

func checkAccountCredentials(profile string) {
	session, _ := session.NewSessionWithOptions(session.Options{
		Profile: profile,
	})
	users, err := listUsers(session)
	if err != nil {
		log.Error(err)
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
		checkUsersConsoleLoginAge(session, user)
		checkUsersAccessKeysAge(session, user)
	}
}

func checkUsersConsoleLoginAge(session *session.Session, user *iam.User) {
	if hasLoginProfile(session, user) == true {
		if user.PasswordLastUsed == nil {
			log.Info(fmt.Sprintf("%s Password never used, but user has a login profile", prefix))
			if *activeMode {
				log.Warn(fmt.Sprintf("%s Disabling console access", prefix))
				deleteUserLoginProfile(session, *user.UserName)
			}
		} else if olderThanAge(*user.PasswordLastUsed) {
			log.Info(fmt.Sprintf(
				"%s Password last used %d days ago", prefix, int(now.Sub(*user.PasswordLastUsed).Hours()/24),
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
			log.Info(fmt.Sprintf("%s Access key never used", prefix))
			if *activeMode {
				log.Warn(fmt.Sprintf("%s Removing access key", prefix))
				deleteAccessKeys(session, *key.AccessKeyId)
			}
		} else if olderThanAge(*lastUsed) {
			log.Info(fmt.Sprintf(
				"%s Key %s last used %d days ago", prefix, *key.AccessKeyId, int(now.Sub(*lastUsed).Hours()/24),
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
