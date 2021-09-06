<?php

/**
 * Service class for the CloudmersiveAntivirus scanner instance.
 *
 * Passes the methods "scan" and "version" to a specific handler, according to
 * the configuration.
 */
class Scanner {

  // Constants defining the infection state of a specific file.
  const FILE_IS_UNCHECKED = -1;
  const FILE_IS_CLEAN     = 0;
  const FILE_IS_INFECTED  = 1;

  // Constants defining whether a specific file should be scanned.
  const FILE_IS_SCANNABLE     = TRUE;
  const FILE_IS_NOT_SCANNABLE = FALSE;
  const FILE_SCANNABLE_IGNORE = NULL;

  /**
   * Check whether the anti-virus checks are enabled.
   *
   * @return bool
   *   TRUE if files should be scanned.
   */
  public static function isEnabled() {
    return variable_get('enabled', TRUE);
  }

  /**
   * Check whether files that have not been scanned can be uploaded.
   *
   * @return bool
   *   TRUE if unchecked files are permitted.
   */
  public function allowUncheckedFiles() {
    return Config::OUTAGE_ALLOW_UNCHECKED;
  }

  /**
   * Check whether files that have not been scanned can be uploaded.
   *
   * @return bool
   *   TRUE if unchecked files are permitted.
   */
  public static function isVerboseModeEnabled() {
    return variable_get('verbosity', 0);
  }

  /**
   * Check whether a specific file should be scanned by CloudmersiveAntivirus.
   *
   * Specific files can be excluded from anti-virus scanning, such as:
   * - Image files
   * - Large files that might take a long time to scan
   * - Files uploaded by trusted administrators
   * - Viruses, intended to be deliberately uploaded to a virus database.
   *
   * Files can be excluded from the scans by implementing
   * hook_cloudmersiveantivirus_file_is_scannable().
   *
   * @see hook_cloudmersiveantivirus_file_is_scannable()
   *
   * @return bool
   *   TRUE if a file should be scanned by the anti-virus service.
   */
  public static function isScannable($file) {
    // Check whether this stream-wrapper scheme is scannable.
    $fileuri = file_uri_target($file->destination);
    if (!empty($fileuri)) {
      $scheme = file_uri_scheme($fileuri);
    }
    else {
      $scheme = file_uri_scheme($file->uri);
    }
    $scannable = Scanner::isSchemeScannable($scheme);

    // FILE_SCANNABLE_IGNORE.
    foreach (module_implements('cloudmersiveantivirus_file_is_scannable') as $module) {
      $result = module_invoke($module, 'cloudmersiveantivirus_file_is_scannable', array($file));
      if ($result !== Scanner::FILE_SCANNABLE_IGNORE) {
        $scannable = $result;
      }
    }
    return $scannable;
  }

  /**
   * Scan a file for viruses.
   *
   * @var $file
   *   The file to scan for viruses.
   *
   * @return int
   *   One of the following class constants:
   *   - CLOUDMERSIVEAV_SCANRESULT_UNCHECKED
   *     The file was not scanned.
   *     The CloudmersiveAntivirus service may be unavailable.
   *   - CLOUDMERSIVEAV_SCANRESULT_CLEAN
   *     The file was scanned, and no infection was found.
   *   - CLOUDMERSIVEAV_SCANRESULT_INFECTED
   *     The file was scanned, and found to be infected with a virus.
   */
  public static function scan($file) {

    // Empty files are never infected.
    if ($file->filesize === 0) {
      return Scanner::FILE_IS_CLEAN;
    }

    $config = new Config();
    $scan_mode = variable_get('scanMode', 1);
    switch ($scan_mode) {
      case Config::MODE_EXECUTABLE:
        $scanner = new Executable($config);
        break;

      case Config::MODE_DAEMON:
        $scanner = new DaemonTCPIP($config);
        break;

      case Config::MODE_UNIX_SOCKET:
        $scanner = new DaemonUnixSocket($config);
        break;
    }

    $result = $scanner->scan($file);

    // Prepare to log results.
    $verbose_mode = variable_get('verbosity', 0);
    $outage_action = variable_get('outageAction', 0);
    $virusname = $scanner->virusName();
    $fileuri = $file->uri;
    switch ($result) {
      // Log every infected file.
      case Scanner::FILE_IS_INFECTED:
        watchdog('action', 'Virus %virusname detected in uploaded file %filename.',
          array('%filename' => $fileuri, '%virusname' => $virusname), WATCHDOG_ERROR);
        break;

      // Log clean files if verbose mode is enabled.
      case Scanner::FILE_IS_CLEAN:
        if ($verbose_mode) {
          watchdog('action', 'Uploaded file %filename checked and found clean.', array('%filename' => $fileuri), WATCHDOG_INFO);
        }
        break;

      // Log unchecked files if they are accepted, or verbose mode is enabled.
      case Scanner::FILE_IS_UNCHECKED:
        if ($outage_action === Config::OUTAGE_ALLOW_UNCHECKED) {
          watchdog('action', 'Uploaded file %filename could not be checked, and was uploaded without checking.', array('%filename' => $fileuri), WATCHDOG_NOTICE);
        }
        elseif ($verbose_mode) {
          watchdog('action', 'Uploaded file %filename could not be checked, and was deleted.', array('%filename' => $fileuri), WATCHDOG_INFO);
        }
        break;
    }
    return $result;
  }

  /**
   * Determine whether files of a given scheme should be scanned.
   *
   * @param string $scheme
   *   The machine name of a stream-wrapper scheme, such as "public", or
   *   "youtube".
   *
   * @return bool
   *   TRUE if the scheme should be scanned.
   */
  public static function isSchemeScannable($scheme) {
    if (empty($scheme)) {
      return TRUE;
    }

    // By default all local schemes should be scannable.
    $local_schemes = array_keys(file_get_stream_wrappers(STREAM_WRAPPERS_LOCAL));
    $scheme_is_local = in_array($scheme, $local_schemes);

    // The default can be overridden per scheme.
    $overridden_schemes = variable_get('overridden_schemes', []);
    $scheme_is_overridden = in_array($scheme, $overridden_schemes);

    return ($scheme_is_local xor $scheme_is_overridden);
  }

}
