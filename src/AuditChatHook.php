<?php

namespace Suilven\AuditChatNotifications;

use SilverStripe\Control\Email\Email;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Security;
use SilverStripe\View\ArrayData;
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

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner,
            'EditorGroups' => $effectiveEditorGroups,
            'ViewerGroups' => $effectiveViewerGroups
        ]);
        $message = $arrayData->renderWith('OnAfterPublish');

        $this->notify("{$message}", 'auditor', 'info');
    }

    /**
     * Log a record being unpublished.
     */
    public function onAfterUnpublish()
    {
        error_log('---- on after unpublish ----');
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner
        ]);
        $message = $arrayData->renderWith('OnAfterUnPublish');

        $this->notify("{$message}", 'auditor', 'info');

    }

    /**
     * Log a record being reverted to live.
     */
    public function onAfterRevertToLive()
    {
        error_log('---- on after revert to live ----');
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner
        ]);
        $message = $arrayData->renderWith('OnAfterRevertToLive');

        $this->notify("{$message}", 'auditor', 'info');

    }

    /**
     * Log a record being duplicated.
     */
    public function onAfterDuplicate()
    {
        error_log('---- on after duplicate ----');
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner
        ]);
        $message = $arrayData->renderWith('OnAfterDuplicate');

        $this->notify("{$message}", 'auditor', 'info');

    }

    /**
     * Log a record being deleted.
     */
    public function onAfterDelete()
    {
        error_log('---- on after delete ----');
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner
        ]);
        $message = $arrayData->renderWith('OnAfterDelete');

        $this->notify("{$message}", 'auditor', 'info');
    }

    /**
     * Log a record being restored to stage.
     */
    public function onAfterRestoreToStage()
    {
        error_log('---- on after restore to stage ----');
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

        $arrayData = new ArrayData([
            'Member' => $member,
            'Page' => $this->owner
        ]);
        $message = $arrayData->renderWith('OnAfterRestoreToStage');

        $this->notify("{$message}", 'auditor', 'info');
    }

    /**
     * Log successful login attempts.
     */
    public function afterMemberLoggedIn()
    {
        $arrayData = new ArrayData([
            'Member' => $this->owner
        ]);
        $message = $arrayData->renderWith('AfterMemberLoggedIn');
        $this->notify("{$message}", 'auditor', 'info');

    }

    /**
     * Log successfully restored sessions from "remember me" cookies ("auto login").
     */
    public function memberAutoLoggedIn()
    {
        $arrayData = new ArrayData([
            'Member' => $this->owner
        ]);
        $message = $arrayData->renderWith('AfterMemberAutoLoggedIn');
        $this->notify("{$message}", 'auditor', 'info');
    }

    /**
     * Log failed login attempts.
     */
    public function authenticationFailed($data)
    {
        error_log('AUTHENTICATION FAILED T1');

        // LDAP authentication uses a "Login" POST field instead of Email.
        $login = isset($data['Login'])
            ? $data['Login']
            : (isset($data[Email::class]) ? $data[Email::class] : '');

        $arrayData = new ArrayData([
            'Member' => new ArrayData([
                'Email' => $login,
                'ID' => null
            ])
        ]);

        $message = $arrayData->renderWith('AuthenticationFailed');

        $this->notify("{$message}", 'auditor', 'info');
    }

    public function authenticationFailedUnknownUser($data)
    {
        error_log('AUTHENTICATION FAILED T2');

        // LDAP authentication uses a "Login" POST field instead of Email.
        $login = isset($data['Login'])
            ? $data['Login']
            : (isset($data[Email::class]) ? $data[Email::class] : '');

        $arrayData = new ArrayData([
            'Member' => new ArrayData([
                'Email' => $login,
                'ID' => null
            ])
        ]);

        $message = $arrayData->renderWith('AuthenticationFailedUnknownUser');

        $this->notify("{$message}", 'auditor', 'info');
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

        $this->notify("{$message}", 'auditor', 'info');
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
        $this->notify("{$message}", 'auditor', 'info');

        $arrayData = new ArrayData([
            'Member' => $this->owner
        ]);
        $message = $arrayData->renderWith('AfterMemberLoggedOut');
        $this->notify("{$message}", 'auditor', 'info');

    }
}
