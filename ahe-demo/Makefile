SOURCE_PATH= .
SOURCES= $(SOURCE_PATH)/*.java
BUILD_DIR=build
DOCS_DIR=doc
JARS= libs/jna.jar:libs/ahe.jar

JAVA_HOME= /usr
JAVABIN=$(JAVA_HOME)/bin/java
JAVA_FLAGS= -cp $(BUILD_DIR):libs/:$(JARS)
JAVACBIN=$(JAVA_HOME)/bin/javac
JAVAC_FLAGS= -cp $(BUILD_DIR):libs/:$(JARS) -d $(BUILD_DIR)/


.PHONY: default run-java run-go-fame run-go-fame-decentralized run-python-fame run-python-fame-decentralized run-python-maabe run-nodejs

default: run-go-fame

all: run-java run-go-fame run-go-fame-decentralized run-python-fame run-python-fame-decentralized run-python-maabe run-nodejs

run-java: compile-java
	cd Java; $(JAVABIN) $(JAVA_FLAGS) DemoMaabe

compile-java:
	cd Java; $(JAVACBIN) $(JAVAC_FLAGS) $(SOURCES)

run-go-fame:
	cd Go; KEY_MANAGEMENT=centralized go run demo_fame.go

run-go-fame-decentralized:
	cd Go; KEY_MANAGEMENT=decentralized go run demo_fame.go

run-python-fame:
	cd Python; python3 demo_fame.py

run-python-fame-decentralized:
	cd Python; python3 demo_fame_decentralized.py

run-python-maabe:
	cd Python; python3 demo_maabe.py

run-nodejs:
	cd NodeJS; node demo_fame.js

