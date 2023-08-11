# AHE Android Demo

This repository contains a dummy app that shows how AHE
library can be used on Android devices.

## Run

Simply clone this repository
and import it into Android Studio as a project.

Then create a virtual android machine - for testing we used Pixel 4 API 30 with
Android 11 x86 - and run the app.

## Functionality

This app takes a message and a decryption policy as textbox input and outputs
the encrypted message in a new activity. Behind the scenes in relies on the
`ahe.jar` file, which provides usable Java bindings for `libahe.so` (which is
provided for X86 and ARM architectures).
