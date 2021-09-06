<?php

/**
 * Class of a config item.
 */
class Config {

  const MODE_DAEMON = 0;
  const MODE_EXECUTABLE = 1;
  const MODE_UNIX_SOCKET = 2;

  const MODE_CLOUDMERSIVE = 1;

  const CLOUDMERSIVEANTIVIRUS_OUTAGE_BLOCK_UNCHECKED = 0;
  const CLOUDMERSIVEANTIVIRUS_OUTAGE_ALLOW_UNCHECKED = 1;

  /**
   * Global config options.
   */
  public function enabled() {
    return variable_get('enabled', TRUE);
  }

  /**
   * Global config options.
   */
  public function scanMode() {
    return variable_get('scanMode', 1);
  }

  /**
   * Global config options.
   */
  public function outageAction() {
    return variable_get('outageAction', 0);
  }

  /**
   * Global config options.
   */
  public function verbosity() {
    return variable_get('verbosity', 0);
  }

}
