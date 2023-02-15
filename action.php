<?php

/**
 * Allow regular expressions in ACL entry objects
 *
 * Original idea raised in https://github.com/splitbrain/dokuwiki/issues/1957
 *
 * @license  GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author   Iain Hallam <iain@nineworlds.net>
 */

if (!defined('DOKU_INC')) die();

class action_plugin_aclregex extends DokuWiki_Action_Plugin
{
    /**
     * Register handlers with DokuWiki's event system
     *
     * @param  Doku_Event_Handler  $controller  DokuWiki's event controller object
     *
     * @return  not required
     */
    public function register(Doku_Event_Handler $controller)
    {
        $controller->register_hook('AUTH_ACL_CHECK', 'BEFORE', $this, 'handleACLRegexCheck');
    }

    /**
     * Event handler run before AUTH_ACL_CHECK
     *
     * Modelled on DokuWiki's own auth_aclcheck_cb() in inc/auth.php
     *
     * @param  Doku_Event  $event  Event object by reference
     * @param  mixed       $param  The parameters passed to register_hook
     *
     * @return  int  AUTH_<X>
     */
    public function handleACLRegexCheck(Doku_Event $event, $param)
    {
        // Prevent default event to do our own auth check
        $event->preventDefault();

        // Access event data
        $id     = $event->data['id'];     // @var string   $id
        //dbg('Raw id: ' . $id);
        $user   = $event->data['user'];   // @var string   $user
        //dbg('Raw user: ' . $user);
        $groups = $event->data['groups']; // @var string[] $groups
        //dbg('Raw groups: ' . implode(', ', $groups));

        // Access global variables
        global $conf;     // @var string[]             $conf      The global configuration dictionary
        global $AUTH_ACL; // @var string[]             $AUTH_ACL  Strings matching <object>\t<subject>[ \t]+<permission>
        //dbg('Raw ACLs:' . NL . implode(NL, $AUTH_ACL));
        global $auth;     // @var DokuWiki_Auth_Plugin $auth      The global authentication handler

        // If no ACL is used always return upload rights
        if (! $conf['useacl']) {
            //dbg('Not configured for ACLs');
            $event->result = AUTH_UPLOAD;
            return AUTH_UPLOAD;
        }

        // If no auth is loaded return no rights
        if (! $auth) {
            //dbg('No auth backend loaded');
            $event->result = AUTH_NONE;
            return AUTH_NONE;
        }

        // If no ACLs exist return no rights
        if (! count($AUTH_ACL)) {
            msg('No ACL setup yet! Denying access to everyone.');
            $event->result = AUTH_NONE;
            return AUTH_NONE;
        }

        // Make sure $groups is an array
        if (! is_array($groups)) $groups = array();

        // If user is superuser or in superuser group return admin rights
        if (auth_isadmin($user, $groups)) {
            //dbg('Admin user');
            $event->result = AUTH_ADMIN;
            return AUTH_ADMIN;
        }

        // Clean up user name (and encode any special characters) and groups
        if (! $auth->isCaseSensitive()) {
            $user   = utf8_strtolower($user);
            $groups = array_map('utf8_strtolower', $groups);
        }
        $user   = auth_nameencode($auth->cleanUser($user));
        $groups = array_map(array($auth, 'cleanGroup'), (array) $groups);

        // Make sure groups start with @ and encode any special characters
        foreach ($groups as &$group) {
            $group = '@' . auth_nameencode($group);
        }

        // Add @ALL group
        $groups[] = '@ALL';

        // Add user to match against
        if ($user) $groups[] = $user;
        //dbg('processed user and groups: ' . implode(', ', $groups));

        // Set initial search variables
        $highest_permission = -1;

        // Build ACL parts structure
        $acl_parts_list = array();
        foreach ($AUTH_ACL as $acl) {
            // Ignore comments
            $acl = preg_replace('/#.*$/', '', $acl);
            //dbg('Processing ACL: ' . $acl);

            // Access ACL parts
            list($acl_object, $acl_subject, $acl_permission, $acl_rest) = preg_split('/[ \t]+/', $acl, 4);
            //dbg('Object: ' . $acl_object);
            //dbg('Subject: ' . $acl_subject);
            //dbg('Permission: ' . $acl_permission);
            //dbg('Rest: ' . $acl_rest);

            // Quote ACL object parts that aren't in a regex to treat them literally
            $acl_object_parts = explode('/', $acl_object); // Split on delimiters
            $acl_object = ''; // Rebuild $acl_object from scratch
            foreach ($acl_object_parts as $key => $part) {
                if ($key % 2 == 0) {
                    // Only for even keys counting from 0, i.e., 1st, 3rd, 5th,
                    // etc., which should be the parts outside / delimiters
                    $part = preg_quote($part); // Quote any PCRE special characters
                }

                $acl_object .= $part; // Add back to $acl_object
            }
            $acl_object = '|^' . $acl_object . '$|'; // Add PCRE delimiters to resulting $acl_object
            //dbg('Quoted object: ' . $acl_object);

            // Assign into the ACL parts structure
            $acl_parts_list[] = array(
                'object'     => $acl_object,
                'subject'    => $acl_subject,
                'permission' => $acl_permission,
                'rest'       => $acl_rest
            );
        }

        // Check for exact object matches
        foreach ($acl_parts_list as $acl_parts) {
            $matches = array();  // Empty the matches array
            if (preg_match($acl_parts['object'], $id, $matches)) {
                //dbg('Matched ID ' . $id . ' with search string ' . $acl_parts['object']);

                $line_permission = $this->checkPermission(
                    $groups,
                    $acl_parts['subject'],
                    $matches,
                    $acl_parts['permission']
                );
                //dbg('Line permission returned: ' . $line_permission);

                // The highest permission found is what gets returned
                if ($line_permission > $highest_permission) {
                    //dbg('New highest permission: ' . $line_permission);
                    $highest_permission = $line_permission;
                }
            }
        }

        // If we had a match return it
        if ($highest_permission > -1) {
            //dbg('Permission: ' . $highest_permission);
            $event->result = $highest_permission;
            return $highest_permission;
        }

        // There wasn't an exact match, so check up the tree for namespace matches
        //dbg('No permissions from exact matches - trying namespaces');

        // Set path match string using namespace
        $ns = getNS($id);
        $path = $ns . ':*';
        if ($path == ':*') {
            $path = '*'; // $id is in the root namespace
        }
        //dbg('Path: ' . $path);

        // Loop to work our way up the tree if there's no match first time round
        do {
            foreach ($acl_parts_list as $acl_parts) {
                $matches = array();  // Empty the matches array
                if (preg_match($acl_parts['object'], $path)) {
                    //dbg('Matched namespace path ' . $path . ' with search string ' . $acl_parts['object']);

                    $line_permission = $this->checkPermission(
                        $groups,
                        $acl_parts['subject'],
                        $matches,
                        $acl_parts['permission']
                    );
                    //dbg('Line permission returned: ' . $line_permission);

                    // The highest permission found is what gets returned
                    if ($line_permission > $highest_permission) {
                        //dbg('New highest permission: ' . $line_permission);
                        $highest_permission = $line_permission;
                    }
                }
            }

            // If we had a match return it
            if ($highest_permission > -1) {
                //dbg('Permission: ' . $highest_permission);
                $event->result = $highest_permission;
                return $highest_permission;
            }

            // If we're not already at the root, get the next higher namespace
            if ($path != '*') {
                $ns = getNS($ns);
                $path = $ns . ':*';
                if ($path == ':*') {
                    $path = '*';
                }
                //dbg('Next path: ' . $path);
            } else {
                // We were at the root already but didn't get a match; move on to the next ACL
                msg('No ACL setup yet! Denying access to everyone.');
                break;
            }
        } while (true); // This shouldn't be endless as there are exit conditions in the loop

        // No matches = no permission
        //dbg('Permission: ' . AUTH_NONE);
        $event->result = AUTH_NONE;
        return AUTH_NONE;
    }

    /**
     * Check the resulting permission for user's groups and username
     *
     * @param  string[]  $groups          A list of groups (including the username) to check
     * @param  string    $acl_subject     The subject (user or group) assigned in the ACL
     * @param  string[]  $matches         The pattern matches from the ID match
     * @param  int       $acl_permission  The permission assigned in the ACL
     */
    private function checkPermission($groups, $acl_subject, $matches, $acl_permission)
    {
        // Access global variables
        global $auth;     // @var DokuWiki_Auth_Plugin $auth      The global authentication handler

        //dbg('checkPermission $groups: ' . $groups);
        //dbg('checkPermission $acl_subject: ' . $acl_subject);
        //dbg('checkPermission $acl_permission: ' . $acl_permission);

        // Lowercase acl_subject except @ALL if we can
        if (! $auth->isCaseSensitive() && $acl_subject !== '@ALL') {
            $acl_subject = utf8_strtolower($acl_subject);
        }

        // Replace any placeholders in the subject with parenthesised matches
        $acl_subject = preg_replace_callback(
            '/%25\d+%25/',  // %25 = ASCII 37, or '%'
            function ($pattern) use ($matches) {
                $pattern_index = substr($pattern[0], 1, -1);
                return $matches[$pattern_index];
            },
            $acl_subject,
        );

        // If $acl_subject doesn't contain one of the user's groups or their user name, move on
        // This would be where to change the plugin to support regexes in subjects
        if (! in_array($acl_subject, $groups)) {
            return -1;
        }

        // Don't allow admin permissions from ACLs!
        if ($acl_permission > AUTH_DELETE) {
            $acl_permission = AUTH_DELETE;
        }

        return $acl_permission;
    }
}
