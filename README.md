ACL Regular Expressions
========================================================================

Regular expression support for DokuWiki access control lists

Usage
------------------------------------------------------------------------

Install the plugin; any entries in `acl.auth.php` will now recognise PHP
Perl-Compatible Regular Expressions when surrounded with slashes:

```
:projects:/[0-9]+/:members  @managers  2
```

Known Issues
------------------------------------------------------------------------

At the moment, there's no admin component - editing must be done through
the file system.
