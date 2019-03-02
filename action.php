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

class action_plugin_aclregex extends DokuWiki_Action_Plugin {
 
  /** store original $ACL_AUTH  */
  
  private $ORIG_ACL_AUTH;
  
  /**
   * Register handlers with DokuWiki's event system
   * 
   * @param  Doku_Event_Handler  $controller  DokuWiki's event controller object
   * 
   * @return  not required
   */
  public function register(Doku_Event_Handler $controller) {
    $controller->register_hook('AUTH_ACL_CHECK', 'BEFORE', $this, '_add_acl');
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
  public function _add_acl(Doku_Event $event, $param) {
    // Prevent default event to do our own auth check
    $event->preventDefault();
   
    global $AUTH_ACL;
    global $USERINFO;
    $ORIG_AUTH_ACL = $AUTH_ACL;

    $add_acl_id = ":admin:add_acl";
    
    if (page_exists($add_acl_id)) {
      //$add_acl = file(wikiFN($add_acl_id));
      /* TBD: take care of placeholders */
      //$AUTH_ACL = array_merge($AUTH_ACL, $add_acl);
   }
    
   $res = auth_aclcheck_cb($event->$data);
   
    $AUTH_ACL = $ORIG_AUTH_ACL;
   
   return $res;
   
   }

 /* public function _restore_acl(Doku_Event $event, $param) {
    global $AUTH_ACL;

    $AUTH_ACL = $this->ORIG_AUTH_ACL;

    return 0;
   } */
}
