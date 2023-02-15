ACL Regular Expressions
========================================================================

Regular expression support for DokuWiki access control lists

Documentation can be found at https://www.dokuwiki.org/plugin:aclregex.

Usage
------------------------------------------------------------------------

Install the plugin; any entries in `acl.auth.php` will now recognise PHP
Perl-Compatible Regular Expressions when surrounded with slashes:

```
:projects:/[0-9]+/:members  @managers  2
```

If you include parenthesised patterns in the regex, these will be
available in the user/group section enclosed in `${` and `}`. (This is
the full form in PCRE syntax, but in this plugin it's always required.)
For example:

```
:projects:/([0-9]+)/:members  @${1}_members  2
```

Known Issues
------------------------------------------------------------------------

At the moment, there's no admin component - editing must be done through
the file system.
