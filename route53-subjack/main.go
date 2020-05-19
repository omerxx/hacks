package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/haccer/subjack/subjack"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"strings"
	"sync"
	"time"
)

/*
 * Add
 */
var verbose *bool
var prefix string
var now = time.Now()

func main() {
	var profilesFlag = flag.String("profiles", "default", "An AWS CLI profile name, or comma-separated list for multiple")
	verbose = flag.Bool("verbose", false, "Notify all record sets including non vulnerable")
	flag.Parse()

	var profiles = strings.Split(*profilesFlag, ",")
	for _, profile := range profiles {
		checkSubdomainTakeovers(profile)
	}
}

func checkSubdomainTakeovers(profile string) {
	session, _ := session.NewSessionWithOptions(session.Options{
		Profile:           profile,
		SharedConfigState: session.SharedConfigEnable,
	})

	// 1. List hostedzones
	// 2. Fetch hostedzones entries (CNAME)
	// 3. Validate subjacks
	hostedZones, err := listHostedZones(session)
	if err != nil {
		logrus.Fatal(err)
	}

	logger := logrus.New()
	log := logger.WithField("appname", "hostedZone")
	if *verbose {
		log.Logger.SetLevel(logrus.DebugLevel)
	}
	var wg sync.WaitGroup
	for _, zone := range hostedZones {
		if !(*zone.Config.PrivateZone) {
			wg.Add(1)
			go checkHostedZone(session, *zone.Id, log, &wg)
		}
	}
	wg.Wait()
}

func listHostedZones(session *session.Session) ([]*route53.HostedZone, error) {
	svc := route53.New(session)
	input := &route53.ListHostedZonesInput{}
	hostedZones, err := svc.ListHostedZones(input)
	if err != nil {
		return nil, err
	}
	return hostedZones.HostedZones, nil
}

func checkHostedZone(session *session.Session, zoneID string, log *logrus.Entry, wg *sync.WaitGroup) {
	recordSets, _ := listRecordSets(session, zoneID)
	recordSetLog := logrus.New().WithField("app", "1")
	recordSetLog.Logger.SetLevel(logrus.DebugLevel)

	var fingerprints []subjack.Fingerprints
	config, _ := ioutil.ReadFile("./fingerprints.json")
	json.Unmarshal(config, &fingerprints)

	var wg2 sync.WaitGroup
	for _, subdomain := range recordSets {
		// if *subdomain.Name == "." {
		// 	log.Infof("Calling %s", *subdomain.Name)
		wg2.Add(1)
		go checkRecordSet(*subdomain.Name, recordSetLog, fingerprints, &wg2)
		// }
	}
	wg2.Wait()
	wg.Done()
}

func checkRecordSet(subdomain string, log *logrus.Entry, fingerprints []subjack.Fingerprints, wg2 *sync.WaitGroup) {
	trimmed := strings.TrimSuffix(subdomain, ".")
	service := subjack.Identify(trimmed, false, false, 10, fingerprints)
	if service != "" {
		service = strings.ToLower(service)
		log.Infof("%s is pointing to a vulnerable %s service.\n", trimmed, service)
	} else {
		if *verbose {
			log.Debugf(fmt.Sprintf("%s is ok\n", subdomain))
		}
	}
	wg2.Done()
}

func listRecordSets(session *session.Session, zoneID string) ([]*route53.ResourceRecordSet, error) {
	var recordSets []*route53.ResourceRecordSet
	var fileterdRecordSets []*route53.ResourceRecordSet
	svc := route53.New(session)
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}
	result, err := svc.ListResourceRecordSets(input)
	if err != nil {
		return nil, err
	}
	recordSets = result.ResourceRecordSets
	isTruncated := *result.IsTruncated
	for isTruncated {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId:    aws.String(zoneID),
			StartRecordName: aws.String(*result.NextRecordName),
		}
		result, err = svc.ListResourceRecordSets(input)
		if err != nil {
			return nil, err
		}
		recordSets = append(recordSets, result.ResourceRecordSets...)
		isTruncated = *result.IsTruncated
	}

	for _, record := range recordSets {
		if *record.Type == "CNAME" {
			fileterdRecordSets = append(fileterdRecordSets, record)
		}
	}
	return fileterdRecordSets, nil
}
