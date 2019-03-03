<?php
/**
 * Allow regular expressions in ACL entry objects
 * 
 * Original idea raised in https://github.com/splitbrain/dokuwiki/issues/1957
 * 
 * @license  GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author   Iain Hallam <iain@nineworlds.net>
 */

if(!defined('DOKU_INC')) die();

/* import auth.php, to call the original function auth_aclcheck_cb */
require_once(DOKU_INC . 'inc/auth.php');

class action_plugin_aclregex extends DokuWiki_Action_Plugin {

  /**
   * Register handlers with DokuWiki's event system
   * 
   * @param  Doku_Event_Handler  $controller  DokuWiki's event controller object
   * 
   * @return  not required
   */
  public function register(Doku_Event_Handler $controller) {
    $controller->register_hook('AUTH_ACL_CHECK', 'BEFORE', $this, '_handle_aclregex_check');
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
  public function _handle_aclregex_check(Doku_Event $event, $param) { 
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
    global $AUTH_ACL; // @var string[]             $AUTH_ACL  Strings in the form <object>\t<subject>[ \t]+<permission>
    //dbg('Raw ACLs:' . NL . implode(NL, $AUTH_ACL));
    global $auth;     // @var DokuWiki_Auth_Plugin $auth      The global authentication handler

    /* load and process additional ACL rules */
    $add_ACL_id = $this->getConf('add_acl_page');
    $auth_ACL = $AUTH_ACL;
    if (page_exists($add_ACL_id)) {
      $add_ACL = file(wikiFN($add_ACL_id));
      $auth_ACL = array_merge($auth_ACL, $add_ACL);
      $add_ACL = $this->_replace_placeholders($add_ACL);
      /* TBD: consider also handling regex */
     }
    
    // temporarily set global $AUTH_ACL to new value, then call auth_aclcheck_cb, then set to original
    $orig_auth_ACL = $AUTH_ACL;
    $AUTH_ACL = $auth_ACL;
    $event->result = auth_aclcheck_cb($event->data);
    $AUTH_ACL = $orig_auth_ACL;  
    
    return $event->result;
  }
  
  
  public function _replace_placeholders($acl) { 
    global $INPUT;
    global $USERINFO;
    
    $out = array();
    foreach($acl as $line) {
        $line = trim($line);
        if(empty($line) || ($line{0} == '#')) continue; // skip blank lines & comments
        list($id,$rest) = preg_split('/[ \t]+/',$line,2);
         
        // substitute user wildcard first (its 1:1)
        if(strstr($line, '%USER%')){
            // if user is not logged in, this ACL line is meaningless - skip it
            if (!$INPUT->server->has('REMOTE_USER')) continue;
            $id   = str_replace('%USER%',cleanID($INPUT->server->str('REMOTE_USER')),$id);
            $rest = str_replace('%USER%',auth_nameencode($INPUT->server->str('REMOTE_USER')),$rest);
        }
        // substitute user NAME wildcard 
        if(strstr($id, '%NAME%')){
            // if user is not logged in, this ACL line is meaningless - skip it
            if (!$INPUT->server->has('REMOTE_USER')) continue;
            $id   = str_replace('%NAME%',cleanID($USERINFO['name']),$id);
        }

        // substitute user NAME wildcard 
        if(strstr($id, '%EMAIL%') || strstr($id, '%EMAILSHORT%') || strstr($id, '%EMAILNAME%')){
              if (!$INPUT->server->has('REMOTE_USER')) continue;
  
              $email = $USERINFO['mail'];
              $email_parts = preg_split("/@/", $email);
              $email_short = $email_parts[0];
              if (preg_match('/student/', $email_parts[1])) {
                  $email_short = $email_short.'_student';
              }
          
              $id   = str_replace('%EMAIL%',cleanID($email),$id);
              $id   = str_replace('%EMAILSHORT%',cleanID($email_short),$id);
              $id   = str_replace('%EMAILNAME%',cleanID($email_parts[0]),$id);
        }

        // substitute group wildcard (its 1:m)
        if(strstr($line, '%GROUP%')){
            // if user is not logged in, grps is empty, no output will be added (i.e. skipped)
            foreach((array) $USERINFO['grps'] as $grp){
                $nid   = str_replace('%GROUP%',cleanID($grp),$id);
                $nrest = str_replace('%GROUP%','@'.auth_nameencode($grp),$rest);
                $out[] = "$nid\t$nrest";
            }
        } else {
            $out[] = "$id\t$rest";
        }
    }
    return $out;
  }
}
