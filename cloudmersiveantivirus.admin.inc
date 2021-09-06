<?php

/**
 * @file
 * Administration page callbacks for the cloud mersive antivirus module.
 */

/**
 * Form constructor for the cloud mersive antivirus system settings.
 *
 * @see cloud_mersive_antivirus_admin_form_submit()
 * @ingroup forms
 */
function cloud_mersive_antivirus_admin_form($form, $form_state) {
  // Global aggregator settings.
  $form['enabled'] = array(
    '#type' => 'checkbox',
    '#title' => t('Enable Cloudmersive Anti-virus integration'),
    '#default_value' => variable_get('enabled', TRUE),
  );

  $form['scan_mechanism_wrapper'] = array(
    '#type' => 'fieldset',
    '#title' => t('Scan mechanism'),
    '#collapsed' => TRUE,
  );

  $form['scan_mechanism_wrapper']['scanMode'] = array(
    '#type' => 'radios',
    '#title' => t('Scan mechanism'),
    '#options' => array(
      Config::MODE_CLOUDMERSIVE => t('Cloudmersive Anti-virus API'),
    ),
    '#default_value' => variable_get('scanMode', 1),
    '#description' => t("Configure how Drupal connects to Cloudmersive Anti-virus. <a href='https://account.cloudmersive.com/signup'>Get key now</a>"),
  );

  // Configuration if CloudmersiveAntivirus is set to Executable mode.
  $form['scan_mechanism_wrapper']['mode_executable'] = array(
    '#type' => 'fieldset',
    '#title' => t('Cloudmersive Anti-virus API configuration'),
    '#collapsed' => TRUE,

    '#states' => array(
      'visible' => array(
        ':input[name="scanMode"]' => array('checked' => TRUE),
      ),
    ),
  );
  $form['scan_mechanism_wrapper']['mode_executable']['executable_path'] = array(
    '#type' => 'textfield',
    '#title' => t('Cloudmersive Anti-virus API Key'),
    '#default_value' => variable_get('mode_executable.executable_path', ''),
    '#maxlength' => 255,
  );
  $form['outageActionsWrapper'] = array(
    '#type' => 'fieldset',
    '#title' => t('Outage behaviour'),
    '#collapsed' => TRUE,
  );
  $form['outageActionsWrapper']['outageAction'] = array(
    '#type' => 'radios',
    '#title' => t('Behaviour when Cloudmersive Antivirus API is unavailable'),
    '#options' => array(
      Config::CLOUDMERSIVEANTIVIRUS_OUTAGE_BLOCK_UNCHECKED => t('Block unchecked files'),
      Config::CLOUDMERSIVEANTIVIRUS_OUTAGE_ALLOW_UNCHECKED => t('Allow unchecked files'),
    ),
    '#default_value' => variable_get('outageAction', 0),
  );
  $form['outageActionsWrapper']['curlTimeoutValue'] = array(
    '#type' => 'textfield',
    '#title' => t('Curl timeout value (in seconds)'),
    '#attributes' => array(
      ' type' => 'number',
      'min' => 30,
      'max' => 300,
      'step' => 10,
    ),
    '#default_value' => variable_get('curl_timeout_value', 30),
  );

  // Allow scanning according to scheme-wrapper.
  $form['schemes'] = array(
    '#type' => 'fieldset',
    '#title' => 'Scannable schemes / stream wrappers',
    '#collapsed' => TRUE,
    '#description' => t("By default only <a href='https://api.drupal.org/api/drupal/includes!stream_wrappers.inc/7'>STREAM_WRAPPERS_LOCAL</a> schemes are scannable."),
  );

  $local_schemes  = scheme_wrappers_available('local');
  $remote_schemes = scheme_wrappers_available('remote');

  if (count($local_schemes)) {
    $form['schemes']['cloudmersiveantivirus_local_schemes'] = array(
      '#type' => 'checkboxes',
      '#title' => t('Local schemes'),
      '#options' => $local_schemes,
      '#default_value' => scheme_wrappers_to_scan('local'),
    );
  }
  if (count($remote_schemes)) {
    $form['schemes']['cloudmersiveantivirus_remote_schemes'] = array(
      '#type' => 'checkboxes',
      '#title' => t('Remote schemes'),
      '#options' => $remote_schemes,
      '#default_value' => scheme_wrappers_to_scan('remote'),
    );
  }

  $form['verbosity_wrapper'] = array(
    '#type' => 'fieldset',
    '#title' => t('Verbosity'),
    '#collapsed' => TRUE,
  );
  $form['verbosity_wrapper']['verbosity'] = array(
    '#type' => 'checkbox',
    '#title' => t('Verbose'),
    '#description' => t('Verbose mode will log all scanned files, including files which pass the Cloudmersive Antivirus scan.'),
    '#default_value' => variable_get('verbosity', 0),
  );

  $form['actions'] = array('#type' => 'actions');
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save configuration'),
  );

  return $form;
}

/**
 * Form validation handler for cloud_mersive_antivirus().
 *
 * @see cloud_mersive_antivirus_admin_form_submit()
 */
function cloud_mersive_antivirus_admin_form_validate($form, &$form_state) {

}

/**
 * Form submission handler for cloud_mersive_antivirus_admin_form().
 */
function cloud_mersive_antivirus_admin_form_submit($form, &$form_state) {
  drupal_set_message(t('The configuration options have been saved.'));

  $local_schemes_to_scan  = isset($form_state['values']['cloudmersiveantivirus_local_schemes']) ? $form_state['values']['cloudmersiveantivirus_local_schemes'] : [];
  $remote_schemes_to_scan = isset($form_state['values']['cloudmersiveantivirus_remote_schemes']) ? $form_state['values']['cloudmersiveantivirus_remote_schemes'] : [];

  $overridden_schemes = array_merge(
      get_overridden_schemes('local', $local_schemes_to_scan),
      get_overridden_schemes('remote', $remote_schemes_to_scan)
    );

  variable_set('enabled', $form_state['values']['enabled']);
  variable_set('outageAction', $form_state['values']['outageAction']);
  variable_set('curl_timeout_value', $form_state['values']['curlTimeoutValue']);
  variable_set('scanMode', $form_state['values']['scanMode']);
  variable_set('verbosity', $form_state['values']['verbosity']);
  variable_set('mode_executable.executable_path', $form_state['values']['executable_path']);
  system_settings_form_submit($form, $form_state);
}

/**
 * List the available stream-wrappers, according to whether.
 *
 * Thestream-wrapper is local or remote.
 *
 * @param string $type
 *   Either 'local' (for local stream-wrappers), or 'remote'.
 *
 * @return array
 *   Array of the names of scheme-wrappers, indexed by the machine-name of
 *   the scheme-wrapper.
 *   For example: array('public' => 'public://').
 */
function scheme_wrappers_available($type) {
  switch ($type) {
    case 'local':
      $schemes = file_get_stream_wrappers(STREAM_WRAPPERS_LOCAL);
      break;

    case 'remote':
      $schemes = array_diff_key(file_get_stream_wrappers(STREAM_WRAPPERS_ALL), file_get_stream_wrappers(STREAM_WRAPPERS_LOCAL));
      break;
  }
  $options = array();
  $schemes_val = array_keys($schemes);
  foreach ($schemes_val as $scheme) {
    $options[$scheme] = $scheme . '://';
  }
  return $options;
}

/**
 * List the stream-wrapper schemes that are configured to be scannable.
 *
 * According to whether the scheme is local or remote.
 *
 * @param string $type
 *   Either 'local' (for local stream-wrappers), or 'remote'.
 *
 * @return array
 *   Unindexed array of the machine-names of stream-wrappers that should be
 *   scanned.
 *   For example: array('public', 'private').
 */
function scheme_wrappers_to_scan($type) {

  switch ($type) {
    case 'local':
      $schemes = array_keys(scheme_wrappers_available('local'));
      break;

    case 'remote':
      $schemes = array_keys(scheme_wrappers_available('remote'));
      break;
  }
  return array_filter($schemes, array('Scanner', 'isSchemeScannable'));
}

/**
 * List which schemes have been overridden.
 *
 * @param string $type
 *   Type of stream-wrapper: either 'local' or 'remote'.
 * @param array $schemes_to_scan
 *   Unindexed array, listing the schemes that should be scanned.
 *
 * @return array
 *   List of the schemes that have been overridden for this particular
 *   stream-wrapper type.
 */
function get_overridden_schemes($type, array $schemes_to_scan) {
  $available_schemes = scheme_wrappers_available($type);
  switch ($type) {
    case 'local':
      $overridden = array_diff_key($available_schemes, $schemes_to_scan);
      return array_keys($overridden);

    case 'remote':
      $overridden = array_intersect_key($available_schemes, $schemes_to_scan);
      return array_keys($overridden);
  }
}
