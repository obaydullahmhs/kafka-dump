/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	kafkaUsername         string
	kafkaPassword         string
	brokers               *string
	topics                string
	kafkaSecurityProtocol *string
	kafkaSaslMechanism    string
	sslCaLocation         string
	sslKeyLocation        string
	sslCertLocation       string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kafka-dump",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	rootCmd.PersistentFlags().StringVarP(&kafkaUsername, "username", "u", "", "Kafka sasl username")
	rootCmd.PersistentFlags().StringVarP(&kafkaPassword, "password", "p", "", "Kafka sasl password")
	rootCmd.PersistentFlags().StringVarP(brokers, "brokers", "b", "", "Kafka brokers address(bootstrap servers)")
	err := rootCmd.MarkFlagRequired("brokers")
	if err != nil {
		return
	}
	rootCmd.PersistentFlags().StringVarP(&topics, "topics", "t", "*", "Kafka topics list comma separated(* for all topics)")
	rootCmd.PersistentFlags().StringVarP(kafkaSecurityProtocol, "security-protocol", "sp", "PLAIN", "Kafka security protocol(E.g. SASL_PLAINTEXT, SASL_SSL, PLAIN, SSL)")
	rootCmd.PersistentFlags().StringVarP(&kafkaSaslMechanism, "sasl-mechanism", "sm", "PLAIN", "Kafka sasl mechanism(E.g. PLAIN, SCRAM-SHA-256, SCRAM-SHA-512)")
	rootCmd.PersistentFlags().StringVar(&sslCaLocation, "ssl-ca-location", "", "Kafka ssl ca location")
	rootCmd.PersistentFlags().StringVar(&sslKeyLocation, "ssl-key-location", "", "Kafka ssl key location")
	rootCmd.PersistentFlags().StringVar(&sslCertLocation, "ssl-cert-location", "", "Kafka ssl cert location")

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kafka-dump.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
