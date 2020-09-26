---
title: "Pentesting OWASP Juice Shop using Burp Suite"
header:
  teaser: /assets/images/2020-07-26-17-20-20.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Hacking
tags:
  - Kali
  - Offensive Security
---

![kali-custom-desktop](/assets/images/2020-07-26-17-20-20.png)

## Kali Information

For the following guide, I use the pre-built image from Offensive Security for VirtualBox. See [this guide](https://pencer.io/guides/cyber-kali-install/) where I went through the steps of importing that image if you need help.

## OWASP Information

From their website [here](https://owasp.org/) they say:

```text
The Open Web Application Security Project® (OWASP) is a nonprofit foundation that works to improve the security of software. Through community-led open source software projects, hundreds of local chapters worldwide, tens of thousands of members, and leading educational and training conferences, the OWASP Foundation is the source for developers and technologists to secure the web.
```

If you look [here](https://owasp.org/projects/) you'll see the list of projects they maintain is pretty impressive. For today we will be looking at [Juice Shop](https://owasp.org/www-project-juice-shop/). The description of it is:

```text
OWASP Juice Shop is probably the most modern and sophisticated insecure web application! It can be used in security trainings, awareness demos, CTFs and as a guinea pig for security tools! Juice Shop encompasses vulnerabilities from the entire OWASP Top Ten along with many other security flaws found in real-world applications!
```

You can find the many different releases of Juice Shop [here](https://github.com/bkimminich/juice-shop/releases/) on Github. The version we want to use is [this one](https://github.com/bkimminich/juice-shop/releases/download/v11.1.2/juice-shop-11.1.2_node10_linux_x64.tgz) because it uses NodeJS version 10, which is what we have in the Kali repository. We could go to a newer version and install NodeJS and NPM from sources, but for the purposes of this guide let's keep it simple.

## Install NodeJS and NPM

The 



kali@kali:~$ sudo apt update
Hit:1 http://kali.download/kali kali-rolling InRelease
Reading package lists... Done
Building dependency tree       
Reading state information... Done
All packages are up to date.
kali@kali:~$ sudo apt upgrade
Reading package lists... Done
Building dependency tree       
Reading state information... Done
Calculating upgrade... Done
The following packages were automatically installed and are no longer required:
  gyp libjs-inherits libjs-is-typedarray libjs-psl libjs-typedarray-to-buffer libnode-dev libnode64 libssl-dev libx264-159 nodejs-doc
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
kali@kali:~$ sudo apt install nodejs
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages were automatically installed and are no longer required:
  gyp libjs-inherits libjs-is-typedarray libjs-psl libjs-typedarray-to-buffer libnode-dev libssl-dev libx264-159
Use 'sudo apt autoremove' to remove them.
Suggested packages:
  npm
The following NEW packages will be installed:
  nodejs
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 88.4 kB of archives.
After this operation, 161 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 nodejs amd64 10.21.0~dfsg-1 [88.4 kB]
Fetched 88.4 kB in 0s (196 kB/s)
Selecting previously unselected package nodejs.
(Reading database ... 323307 files and directories currently installed.)
Preparing to unpack .../nodejs_10.21.0~dfsg-1_amd64.deb ...
Unpacking nodejs (10.21.0~dfsg-1) ...
Setting up nodejs (10.21.0~dfsg-1) ...
update-alternatives: using /usr/bin/nodejs to provide /usr/bin/js (js) in auto mode
Processing triggers for kali-menu (2020.3.2) ...
Processing triggers for man-db (2.9.3-2) ...
kali@kali:~$ sudo apt install npm
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following package was automatically installed and is no longer required:
  libx264-159
Use 'sudo apt autoremove' to remove it.
The following additional packages will be installed:
  node-abbrev node-ajv node-ansi node-ansi-align node-ansi-regex node-ansi-styles node-ansistyles node-aproba node-archy node-are-we-there-yet node-asap node-asn1 node-assert-plus node-asynckit node-aws-sign2 node-aws4
  node-balanced-match node-bcrypt-pbkdf node-bl node-bluebird node-boxen node-brace-expansion node-builtin-modules node-builtins node-cacache node-call-limit node-camelcase node-caseless node-chalk node-chownr node-ci-info
  node-cli-boxes node-cliui node-clone node-co node-color-convert node-color-name node-colors node-columnify node-combined-stream node-concat-map node-concat-stream node-config-chain node-configstore node-console-control-strings
  node-copy-concurrently node-core-util-is node-cross-spawn node-crypto-random-string node-cyclist node-dashdash node-debbundle-es-to-primitive node-debug node-decamelize node-decompress-response node-deep-extend node-defaults
  node-define-properties node-delayed-stream node-delegates node-detect-indent node-detect-newline node-dot-prop node-duplexer3 node-duplexify node-ecc-jsbn node-editor node-encoding node-end-of-stream node-err-code node-errno
  node-es6-promise node-escape-string-regexp node-execa node-extend node-extsprintf node-fast-deep-equal node-find-up node-flush-write-stream node-forever-agent node-form-data node-from2 node-fs-vacuum node-fs-write-stream-atomic
  node-fs.realpath node-function-bind node-gauge node-genfun node-get-caller-file node-get-stream node-getpass node-glob node-got node-graceful-fs node-gyp node-har-schema node-har-validator node-has-flag node-has-symbol-support-x
  node-has-to-string-tag-x node-has-unicode node-hosted-git-info node-http-signature node-iconv-lite node-iferr node-import-lazy node-imurmurhash node-inflight node-inherits node-ini node-invert-kv node-ip node-ip-regex node-is-npm
  node-is-obj node-is-object node-is-path-inside node-is-plain-obj node-is-retry-allowed node-is-stream node-is-typedarray node-isarray node-isexe node-isstream node-isurl node-jsbn node-json-parse-better-errors node-json-schema
  node-json-schema-traverse node-json-stable-stringify node-json-stringify-safe node-jsonify node-jsonparse node-jsonstream node-jsprim node-latest-version node-lazy-property node-lcid node-libnpx node-locate-path node-lockfile
  node-lodash node-lodash-packages node-lowercase-keys node-lru-cache node-make-dir node-mem node-mime node-mime-types node-mimic-fn node-mimic-response node-minimatch node-minimist node-mississippi node-mkdirp node-move-concurrently
  node-ms node-mute-stream node-nopt node-normalize-package-data node-npm-bundled node-npm-package-arg node-npm-run-path node-npmlog node-number-is-nan node-oauth-sign node-object-assign node-once node-opener node-os-locale
  node-os-tmpdir node-osenv node-p-cancelable node-p-finally node-p-is-promise node-p-limit node-p-locate node-p-timeout node-package-json node-parallel-transform node-path-exists node-path-is-absolute node-path-is-inside
  node-performance-now node-pify node-prepend-http node-process-nextick-args node-promise-inflight node-promise-retry node-promzard node-proto-list node-prr node-pseudomap node-psl node-pump node-pumpify node-punycode node-qs node-qw
  node-rc node-read node-read-package-json node-readable-stream node-registry-auth-token node-registry-url node-request node-require-directory node-require-main-filename node-resolve node-resolve-from node-retry node-rimraf
  node-run-queue node-safe-buffer node-semver node-semver-diff node-set-blocking node-sha node-shebang-command node-shebang-regex node-signal-exit node-slash node-slide node-sorted-object node-spdx-correct node-spdx-exceptions
  node-spdx-expression-parse node-spdx-license-ids node-sshpk node-ssri node-stream-each node-stream-iterate node-stream-shift node-strict-uri-encode node-string-decoder node-string-width node-strip-ansi node-strip-eof
  node-strip-json-comments node-supports-color node-tar node-term-size node-text-table node-through node-through2 node-timed-out node-tough-cookie node-tunnel-agent node-tweetnacl node-typedarray node-typedarray-to-buffer
  node-uid-number node-unique-filename node-unique-string node-unpipe node-uri-js node-url-parse-lax node-url-to-options node-util-deprecate node-uuid node-validate-npm-package-license node-validate-npm-package-name node-verror
  node-wcwidth.js node-which node-which-module node-wide-align node-widest-line node-wrap-ansi node-wrappy node-write-file-atomic node-xdg-basedir node-xtend node-y18n node-yallist node-yargs node-yargs-parser
The following NEW packages will be installed:
  node-abbrev node-ajv node-ansi node-ansi-align node-ansi-regex node-ansi-styles node-ansistyles node-aproba node-archy node-are-we-there-yet node-asap node-asn1 node-assert-plus node-asynckit node-aws-sign2 node-aws4
  node-balanced-match node-bcrypt-pbkdf node-bl node-bluebird node-boxen node-brace-expansion node-builtin-modules node-builtins node-cacache node-call-limit node-camelcase node-caseless node-chalk node-chownr node-ci-info
  node-cli-boxes node-cliui node-clone node-co node-color-convert node-color-name node-colors node-columnify node-combined-stream node-concat-map node-concat-stream node-config-chain node-configstore node-console-control-strings
  node-copy-concurrently node-core-util-is node-cross-spawn node-crypto-random-string node-cyclist node-dashdash node-debbundle-es-to-primitive node-debug node-decamelize node-decompress-response node-deep-extend node-defaults
  node-define-properties node-delayed-stream node-delegates node-detect-indent node-detect-newline node-dot-prop node-duplexer3 node-duplexify node-ecc-jsbn node-editor node-encoding node-end-of-stream node-err-code node-errno
  node-es6-promise node-escape-string-regexp node-execa node-extend node-extsprintf node-fast-deep-equal node-find-up node-flush-write-stream node-forever-agent node-form-data node-from2 node-fs-vacuum node-fs-write-stream-atomic
  node-fs.realpath node-function-bind node-gauge node-genfun node-get-caller-file node-get-stream node-getpass node-glob node-got node-graceful-fs node-gyp node-har-schema node-har-validator node-has-flag node-has-symbol-support-x
  node-has-to-string-tag-x node-has-unicode node-hosted-git-info node-http-signature node-iconv-lite node-iferr node-import-lazy node-imurmurhash node-inflight node-inherits node-ini node-invert-kv node-ip node-ip-regex node-is-npm
  node-is-obj node-is-object node-is-path-inside node-is-plain-obj node-is-retry-allowed node-is-stream node-is-typedarray node-isarray node-isexe node-isstream node-isurl node-jsbn node-json-parse-better-errors node-json-schema
  node-json-schema-traverse node-json-stable-stringify node-json-stringify-safe node-jsonify node-jsonparse node-jsonstream node-jsprim node-latest-version node-lazy-property node-lcid node-libnpx node-locate-path node-lockfile
  node-lodash node-lodash-packages node-lowercase-keys node-lru-cache node-make-dir node-mem node-mime node-mime-types node-mimic-fn node-mimic-response node-minimatch node-minimist node-mississippi node-mkdirp node-move-concurrently
  node-ms node-mute-stream node-nopt node-normalize-package-data node-npm-bundled node-npm-package-arg node-npm-run-path node-npmlog node-number-is-nan node-oauth-sign node-object-assign node-once node-opener node-os-locale
  node-os-tmpdir node-osenv node-p-cancelable node-p-finally node-p-is-promise node-p-limit node-p-locate node-p-timeout node-package-json node-parallel-transform node-path-exists node-path-is-absolute node-path-is-inside
  node-performance-now node-pify node-prepend-http node-process-nextick-args node-promise-inflight node-promise-retry node-promzard node-proto-list node-prr node-pseudomap node-psl node-pump node-pumpify node-punycode node-qs node-qw
  node-rc node-read node-read-package-json node-readable-stream node-registry-auth-token node-registry-url node-request node-require-directory node-require-main-filename node-resolve node-resolve-from node-retry node-rimraf
  node-run-queue node-safe-buffer node-semver node-semver-diff node-set-blocking node-sha node-shebang-command node-shebang-regex node-signal-exit node-slash node-slide node-sorted-object node-spdx-correct node-spdx-exceptions
  node-spdx-expression-parse node-spdx-license-ids node-sshpk node-ssri node-stream-each node-stream-iterate node-stream-shift node-strict-uri-encode node-string-decoder node-string-width node-strip-ansi node-strip-eof
  node-strip-json-comments node-supports-color node-tar node-term-size node-text-table node-through node-through2 node-timed-out node-tough-cookie node-tunnel-agent node-tweetnacl node-typedarray node-typedarray-to-buffer
  node-uid-number node-unique-filename node-unique-string node-unpipe node-uri-js node-url-parse-lax node-url-to-options node-util-deprecate node-uuid node-validate-npm-package-license node-validate-npm-package-name node-verror
  node-wcwidth.js node-which node-which-module node-wide-align node-widest-line node-wrap-ansi node-wrappy node-write-file-atomic node-xdg-basedir node-xtend node-y18n node-yallist node-yargs node-yargs-parser npm
0 upgraded, 278 newly installed, 0 to remove and 0 not upgraded.
Need to get 3,625 kB of archives.
After this operation, 25.2 MB of additional disk space will be used.
Do you want to continue? [Y/n] 
<<SNIP>>
Setting up node-duplexify (4.1.1-1) ...
Setting up node-spdx-correct (3.1.1-1) ...
Setting up node-wrap-ansi (4.0.0-2) ...
Setting up node-glob (7.1.6-1) ...
Setting up node-get-stream (4.1.0-1) ...
Setting up node-pumpify (2.0.1-1) ...
Setting up node-widest-line (3.1.0-1) ...
Setting up node-got (7.1.0-1) ...
Setting up node-configstore (5.0.1-1) ...
Setting up node-package-json (4.0.1-1) ...
Setting up node-latest-version (3.1.0-1) ...
Setting up node-wide-align (1.1.3-1) ...
Setting up node-ansi-align (3.0.0-1) ...
Setting up node-request (2.88.1-4) ...
Setting up node-cliui (4.1.0-2) ...
Setting up node-rimraf (2.6.3-1) ...
Setting up node-validate-npm-package-license (3.0.4-1) ...
Setting up node-stream-each (1.2.3-1) ...
Setting up node-mississippi (3.0.0-1) ...
Setting up node-execa (0.10.0+dfsg-1) ...
Setting up node-copy-concurrently (1.0.5-5) ...
Setting up node-move-concurrently (1.0.1-2) ...
Setting up node-term-size (1.2.0+dfsg-2) ...
Setting up node-os-locale (4.0.0-1) ...
Setting up node-fs-vacuum (1.2.10-3) ...
Setting up node-gauge (2.7.4-1) ...
Setting up node-normalize-package-data (2.5.0-1) ...
Setting up node-boxen (4.2.0-3) ...
Setting up node-npmlog (4.1.2-2) ...
Setting up node-yargs (15.3.1-1) ...
Setting up node-cacache (11.3.3-2) ...
Setting up node-read-package-json (2.1.1-1) ...
Setting up node-gyp (7.0.0-1) ...
Setting up node-libnpx (10.2.1-2) ...
Setting up npm (6.14.6+ds-1) ...
Processing triggers for kali-menu (2020.3.2) ...
Processing triggers for man-db (2.9.3-2) ...
