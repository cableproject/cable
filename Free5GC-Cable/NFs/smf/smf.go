/*
 * Nsmf_PDUSession
 *
 * SMF PDU Session Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/smf/logger"
	"github.com/free5gc/smf/service"
	"github.com/free5gc/version"
)

var SMF = &service.SMF{}

var appLog *logrus.Entry

func init() {
	appLog = logger.AppLog
}

func main() {
	app := cli.NewApp()
	app.Name = "smf"
	fmt.Print(app.Name, "\n")
	appLog.Infoln("SMF version: ", version.GetVersion())
	app.Usage = "-free5gccfg common configuration file -smfcfg smf configuration file"
	app.Action = action
	app.Flags = SMF.GetCliCmd()

	if err := app.Run(os.Args); err != nil {
		appLog.Errorf("SMF Run error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := SMF.Initialize(c); err != nil {
		logger.CfgLog.Errorf("%+v", err)
		return fmt.Errorf("Failed to initialize !!")
	}

	SMF.Start()

	return nil
}