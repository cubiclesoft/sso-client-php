Single Sign On (SSO) Client for PHP
===================================

The official PHP SSO Client for the Barebones SSO Server.

[Barebones SSO Server](https://github.com/cubiclesoft/sso-server) is an awesome, scalable, secure, flexible login system.

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/)

Features
--------

* Average memory footprint.  About 1MB RAM per connection.
* Classes and functions are carefully named to avoid naming conflicts with third-party software.
* When authentication is required prior to executing some task (e.g. posting a comment), the SSO client encrypts and sends the current request data ($_GET, $_POST, etc.) to the SSO server for later retrieval and will resume exactly where it left off in most cases (e.g. the comment is posted).
* Encrypts communications over the network (even HTTP).
* Communicates with the server on a schedule set by the client.  Allows for significantly reduced network overhead without affecting system integrity.
* And more.  See the [full feature list](https://github.com/cubiclesoft/sso-server/blob/master/docs/all-features.md).
* Also has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your project.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

More Information
----------------

* [Barebones SSO Server](https://github.com/cubiclesoft/sso-server)
* [Quick start video tutorials](https://www.youtube.com/watch?v=Vbe4p-PUSTo&index=3&list=PLIvucSFZRDjgiSfsm707zn-bqKd64Eikb)
