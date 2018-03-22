<?php

namespace Suilven\AuditChatNotifications;

use SilverStripe\Control\Email\Email;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Security;
use Suilven\Notifier\NotifyTrait;

/**
 * Provides logging hooks that are inserted into Framework objects.
 */
class AuditChatHook extends DataExtension
{

    use NotifyTrait;

    /**
     * Notify a record being published.
     */
    public function onAfterPublish(&$original)
    {
        error_log('On after publish');

        $member = Security::getcurrentUser();
        error_log('T1');
        if (!$member || !$member->exists()) {
            return false;
        }

        error_log('T2');
        $effectiveViewerGroups = '';
        if ($this->owner->CanViewType === 'OnlyTheseUsers') {
            $effectiveViewerGroups = implode(
                ', ',
                array_values($original->ViewerGroups()->map('ID', 'Title')->toArray())
            );
        }

        error_log('T3');
        if (!$effectiveViewerGroups) {
            $effectiveViewerGroups = $this->owner->CanViewType;
        }

        error_log('T4');
        $effectiveEditorGroups = '';
        if ($this->owner->CanEditType === 'OnlyTheseUsers' && $original->EditorGroups()->exists()) {
            $groups = [];
            foreach ($original->EditorGroups() as $group) {
                $groups[$group->ID] = $group->Title;
            }
            $effectiveEditorGroups = implode(', ', array_values($groups));
        }
        if (!$effectiveEditorGroups) {
            $effectiveEditorGroups = $this->owner->CanEditType;
        }
        error_log('T5');

        $message = sprintf(
            '"%s" (ID: %s) published %s "%s" (ID: %s, Version: %s, ClassName: %s, Effective ViewerGroups: %s, '
            . 'Effective EditorGroups: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID,
            $this->owner->Version,
            $this->owner->ClassName,
            $effectiveViewerGroups,
            $effectiveEditorGroups
        );

        error_log('T6'  . $message);

        $this->notify($message, 'auditor', 'info');
    }

    /**
     * Log a record being unpublished.
     */
    public function onAfterUnpublish()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $message =sprintf(
            '"%s" (ID: %s) unpublished %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        );

        $this->notify($message, 'auditor', 'info');

    }

    /**
     * Log a record being reverted to live.
     */
    public function onAfterRevertToLive()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $message = sprintf(
            '"%s" (ID: %s) reverted %s "%s" (ID: %s) to it\'s live version (#%d)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID,
            $this->owner->Version
        );

        $this->notify($message, 'auditor', 'info');

    }

    /**
     * Log a record being duplicated.
     */
    public function onAfterDuplicate()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $message = sprintf(
            '"%s" (ID: %s) duplicated %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        );

        $this->notify($message, 'auditor', 'info');

    }

    /**
     * Log a record being deleted.
     */
    public function onAfterDelete()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $message = sprintf(
            '"%s" (ID: %s) deleted %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        );

        $this->notify($message, 'auditor', 'info');

    }

    /**
     * Log a record being restored to stage.
     */
    public function onAfterRestoreToStage()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $message = sprintf(
            '"%s" (ID: %s) restored %s "%s" to stage (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        );

        $this->notify($message, 'auditor', 'info');
    }

    /**
     * Log successful login attempts.
     */
    public function afterMemberLoggedIn()
    {
        $message = sprintf(
            '"%s" (ID: %s) successfully logged in',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        );

        $this->notify($message, 'auditor', 'info');

    }

    /**
     * Log successfully restored sessions from "remember me" cookies ("auto login").
     */
    public function memberAutoLoggedIn()
    {
        $message =sprintf(
            '"%s" (ID: %s) successfully restored autologin session',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        );
        $this->notify($message, 'auditor', 'info');
    }

    /**
     * Log failed login attempts.
     */
    public function authenticationFailed($data)
    {
        // LDAP authentication uses a "Login" POST field instead of Email.
        $login = isset($data['Login'])
            ? $data['Login']
            : (isset($data[Email::class]) ? $data[Email::class] : '');

        if (empty($login)) {
            $message = (
                'Could not determine username/email of failed authentication. '.
                'This could be due to login form not using Email or Login field for POST data.'
            );
            $this->notify($message, 'auditor', 'info');
            return;
        }

        $message = sprintf('Failed login attempt using email "%s"', $login);
        $this->notify($message, 'auditor', 'info');

    }

    /**
     * @deprecated 2.1...3.0 Use tractorcow/silverstripe-proxy-db instead
     */
    public function onBeforeInit()
    {
        // no-op
    }

    /**
     * Log permission failures (where the status is set after init of page).
     */
    public function onAfterInit()
    {
        // Suppress errors if dev/build necessary
        if (!Security::database_is_ready()) {
            return false;
        }
        $currentMember = Security::getCurrentUser();
        if (!$currentMember || !$currentMember->exists()) {
            return false;
        }

        $statusCode = $this->owner->getResponse()->getStatusCode();

        if (substr($statusCode, 0, 1) == '4') {
            $this->logPermissionDenied($statusCode, $currentMember);
        }
    }

    protected function logPermissionDenied($statusCode, $member)
    {
        $message =sprintf(
            'HTTP code %s - "%s" (ID: %s) is denied access to %s',
            $statusCode,
            $member->Email ?: $member->Title,
            $member->ID,
            $_SERVER['REQUEST_URI']
        );

        $this->notify($message, 'auditor', 'info');
    }

    /**
     * Log successful logout.
     */
    public function afterMemberLoggedOut()
    {
        $message =sprintf(
            '"%s" (ID: %s) successfully logged out',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        );
        $this->notify($message, 'auditor', 'info');
    }
}
