package main

import (
	"log"
	"os"
)

/*
	Check for an environment variable value, if absent use a default value
*/
func GetOptionalEnv(varName string, optional string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		return optional
	}
	return envVar
}

/*
	Check for an environment variable value, exit program if not found
*/
func GetRequiredEnv(varName string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		log.Fatalf("The required env var %s is not provided. Exiting", varName)
	}
	return envVar
}

/*
	Check for an environment variable value with expected possibilities, exit program if value not expected
*/
func GetExpectedEnv(varName string, expected []string) string {
	envVar := GetRequiredEnv(varName)
	if !contains(expected, envVar) {
		log.Fatalf("The value for env var %s is not expected. Expected values are %v", varName, expected)
	}
	return envVar
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}
