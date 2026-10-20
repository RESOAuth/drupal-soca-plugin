<?php

declare(strict_types=1);

namespace Drupal\soca\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\soca\DrupalFlow;
use RESOAuth\Soca\Bridge\Flow;
use RESOAuth\Soca\Policy;

final class SettingsForm extends ConfigFormBase
{
    public function getFormId(): string { return 'soca_settings'; }
    protected function getEditableConfigNames(): array { return ['soca.settings']; }
    public function buildForm(array $form, FormStateInterface $form_state): array {
        $flow = new DrupalFlow();
        try { $status = json_encode($flow->status(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR); }
        catch (\Throwable $e) { $status = $e->getMessage(); }
        $saved = $this->config('soca.settings')->get('profile') ?? Flow::defaults();
        $form['status'] = ['#type' => 'item', '#title' => $this->t('Effective status'), '#plain_text' => $status];
        $form['profile'] = ['#type' => 'textarea', '#title' => $this->t('Profile JSON'), '#rows' => 22,
            '#default_value' => json_encode($saved, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            '#description' => $this->t('Canonical HTTPS origin, admission rules and opt-in provisioning. Mount secrets using SOCA_PRIVATE_KEY_FILE. SOCA_CONFIG_FILE overrides and locks this form. Save a disabled candidate, check its documents and complete an operator test before enabling.'),
            '#disabled' => (bool) getenv('SOCA_CONFIG_FILE')];
        $form['saved_hash'] = ['#type' => 'hidden', '#default_value' => hash('sha256', json_encode($saved))];
        $form['maintenance'] = ['#type' => 'actions'];
        foreach (['documents' => 'Check public documents', 'test' => 'Start operator test login', 'invalidate' => 'Invalidate pending sign-ins'] as $operation => $label) {
            $form['maintenance'][$operation] = ['#type' => 'submit', '#value' => $this->t($label), '#name' => $operation,
                '#submit' => ['::maintenance'], '#limit_validation_errors' => []];
        }
        $form['association'] = ['#type' => 'details', '#title' => $this->t('Approved identity links')];
        $form['association']['uid'] = ['#type' => 'number', '#title' => $this->t('Local account ID'), '#min' => 2];
        $form['association']['subject'] = ['#type' => 'textfield', '#title' => $this->t('Exact provider subject'), '#maxlength' => 255,
            '#description' => $this->t('Verify ownership independently. Email alone cannot approve a link. The issuer is fixed by the current trusted profile.')];
        foreach (['link' => 'Approve identity link', 'unlink' => 'Remove account link'] as $operation => $label) {
            $form['association'][$operation] = ['#type' => 'submit', '#value' => $this->t($label), '#name' => $operation,
                '#submit' => ['::association'], '#limit_validation_errors' => []];
        }
        return parent::buildForm($form, $form_state);
    }
    public function validateForm(array &$form, FormStateInterface $form_state): void {
        if (getenv('SOCA_CONFIG_FILE')) { return; }
        try {
            $profile = json_decode($form_state->getValue('profile'), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($profile) || array_is_list($profile) || isset($profile['private_key_pem'])) { throw new \RuntimeException('Provide a JSON object without secrets.'); }
            Policy::validate(array_replace(Flow::defaults(), $profile));
            $saved = $this->config('soca.settings')->get('profile') ?? Flow::defaults();
            if (!hash_equals(hash('sha256', json_encode($saved)), $form_state->getValue('saved_hash'))) { throw new \RuntimeException('Configuration changed. Reload before saving.'); }
            // Activation must use the identical saved candidate; enabling alone is not part of its revision.
            $candidate = $profile; unset($candidate['enabled']);
            $previous = $saved; unset($previous['enabled']);
            if (!empty($profile['enabled'])) {
                $status = (new DrupalFlow())->status();
                if ($candidate !== $previous || !$status['documents_checked'] || !$status['test_login_passed']) {
                    throw new \RuntimeException('Save this candidate disabled, then check documents and complete its operator test before enabling.');
                }
            }
            $form_state->set('decoded', $profile);
        } catch (\Throwable $e) { $form_state->setErrorByName('profile', $e->getMessage()); }
    }
    public function submitForm(array &$form, FormStateInterface $form_state): void {
        if (!getenv('SOCA_CONFIG_FILE')) {
            $this->config('soca.settings')->set('profile', $form_state->get('decoded'))->save();
            (new DrupalFlow())->invalidate();
            \Drupal::logger('soca')->notice('SOCA configuration changed by administrator @uid.', ['@uid' => \Drupal::currentUser()->id()]);
        }
        parent::submitForm($form, $form_state);
    }
    public function maintenance(array &$form, FormStateInterface $form_state): void {
        try {
            $flow = new DrupalFlow();
            $operation = $form_state->getTriggeringElement()['#name'];
            if ($operation === 'test') { $form_state->setResponse(new TrustedRedirectResponse($flow->begin(true))); return; }
            if ($operation === 'documents') { $flow->checkDocuments(); }
            if ($operation === 'invalidate') { $flow->invalidate(); }
            $this->messenger()->addStatus($this->t('SOCA maintenance completed.'));
        } catch (\Throwable $e) { $this->messenger()->addError($e->getMessage()); }
        $form_state->setRebuild();
    }
    public function association(array &$form, FormStateInterface $form_state): void {
        try {
            $flow = new DrupalFlow();
            $uid = (int) $form_state->getValue('uid');
            if ($uid < 2) { throw new \RuntimeException('Choose an eligible local account ID.'); }
            if ($form_state->getTriggeringElement()['#name'] === 'link') {
                $flow->link($flow->configuration()['issuer'], (string) $form_state->getValue('subject'), $uid);
            } else {
                \Drupal::database()->delete('soca_links')->condition('uid', $uid)->execute();
                \Drupal::logger('soca')->notice('Administrator @operator removed the identity link for account @uid.',
                    ['@operator' => $flow->operator(), '@uid' => $uid]);
            }
            $this->messenger()->addStatus($this->t('Identity association updated.'));
        } catch (\Throwable $e) { $this->messenger()->addError($this->t('Association failed. Verify the account and any existing links.')); }
        $form_state->setRebuild();
    }
}
