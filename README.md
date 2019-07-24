# pssh-tools

[![Build Status](https://travis-ci.org/feedsbrain/pssh-tools.svg?branch=master)](https://travis-ci.org/feedsbrain/pssh-tools) [![Maintainability](https://api.codeclimate.com/v1/badges/916d04bffb3000cbda7d/maintainability)](https://codeclimate.com/github/feedsbrain/pssh-tools/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/916d04bffb3000cbda7d/test_coverage)](https://codeclimate.com/github/feedsbrain/pssh-tools/test_coverage)

**Tools to generate PSSH Data and PSSH Box**

For dealing with multi-drm using common encryption (cenc) we may need to generate pssh data and/or pssh box to use in our workflow. This tools helpful to easily provide the base64 pssh data for Widevine and PlayReady.

## Installation

This module is installed via npm:

``` bash
$ npm install pssh-tools
```

## Supported PSSH

Currently we're only focus on Widevine and PlayReady but we will support more in the future.
