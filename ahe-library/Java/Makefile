SOURCE_PATH= src/com/arcadian/ahe
SOURCES= $(SOURCE_PATH)/type/*.java $(SOURCE_PATH)/exception/*.java $(SOURCE_PATH)/*.java
TEST_SOURCES= $(SOURCE_PATH)/test/*.java
BUILD_DIR=build
ROOT_BUILD=../build
DOCS_DIR=doc
PACKAGE= com.arcadian.ahe
JARS= libs/jna.jar:libs/junit-4.13.2.jar:libs/hamcrest-core-1.3.jar

JAVA_HOME= /usr
JAVABIN=$(JAVA_HOME)/bin/java
JAVA_FLAGS= -cp $(BUILD_DIR):libs/:$(JARS)
JAVACBIN=$(JAVA_HOME)/bin/javac
JAVAC_FLAGS= -cp $(BUILD_DIR):libs/:$(JARS) -d $(BUILD_DIR)/
JAR_BIN=$(JAVA_HOME)/bin/jar
JAVADOC_BIN=$(JAVA_HOME)/bin/javadoc
JAVADOC_FLAGS= -cp $(BUILD_DIR):libs/:$(JARS) -d $(DOCS_DIR)/

.PHONY: all default compile clean test jar doc

default: compile

compile:
	@mkdir -p libs/linux-x86-64/ $(BUILD_DIR)
	@cp ../prebuild/linux-x86-64/libahe* libs/linux-x86-64/
	$(JAVACBIN) $(JAVAC_FLAGS) $(SOURCES)

jar: clean compile
	$(JAR_BIN) -cvf $(BUILD_DIR)/ahe.jar -C $(BUILD_DIR)/ .
	@cp $(BUILD_DIR)/ahe.jar $(ROOT_BUILD)/ahe.jar

clean:
	@rm -f *.log
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DOCS_DIR)

test:
	@$(JAVACBIN) $(JAVAC_FLAGS) $(SOURCES) $(TEST_SOURCES)
	$(JAVABIN) $(JAVA_FLAGS) org.junit.runner.JUnitCore $(shell find -type f -name "*Test*class" | xargs -I {} basename {} .class | xargs -I {} echo $(PACKAGE).test.{} | xargs)

doc:
	@mkdir -p $(DOCS_DIR)
	$(JAVADOC_BIN) $(JAVADOC_FLAGS) $(SOURCES)
