# Akamai G2O module for Nginx
## nginx_mod_akamai_g2o [![Build Status](https://travis-ci.org/kaltura/nginx_mod_akamai_g2o.svg?branch=master)](https://travis-ci.org/kaltura/nginx_mod_akamai_g2o)

Controls access to content from Akamai edge servers, using the G2O headers: `X-Akamai-G2O-Auth-Data` and `X-Akamai-G2O-Auth-Sign`.

## Installation

Like any other nginx module use the `--add-module` option when configuring:

    ./configure --add-module=$PATH_TO_G2O_DIR
or

    ./configure --add-dynamic-module=$PATH_TO_G2O_DIR
if you want to use it as dynamic module (nginx >= 1.9.11 is required)

It requires OpenSSL.

## Configuration

Place the following settings (`auth_akamai_g2o`, `auth_akamai_g2o_nonce` and `auth_akamai_g2o_key`) into a main, server or location section of your conf file:

    location /download {
        auth_akamai_g2o        on;
        auth_akamai_g2o_nonce  "token";
        auth_akamai_g2o_key    "a_password";
    }

## Testing

Get ruby, then install dependencies:

    bundle

Then run the tests:

    rspec

Write more tests in `spec/*.rb`

## Copyright & License

All code in this project is released under the [BSD license](https://github.com/kaltura/nginx_mod_akamai_g2o/blob/master/LICENSE) unless a different license for a particular library is specified in the applicable library path.
Copyright © NGINX, Tim Macfarlane, Kaltura Inc. and others. All rights reserved.
