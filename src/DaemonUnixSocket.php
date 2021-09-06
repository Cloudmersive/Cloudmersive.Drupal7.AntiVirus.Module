<?php

/**
 * Class of scanner item.
 */
class DaemonUnixSocket {
  /**
   * The file.
   *
   * @var file
   */
  protected $file;
  /**
   * The Unix Socket.
   *
   * @var unixsocket
   */
  protected $unixSocket;
  /**
   * The Virus Name.
   *
   * @var virusname
   */
  protected $virusName = '';

  /**
   * {@inheritdoc}
   */
  public function scan($file) {

    $unix_socket = variable_get('mode_daemon_unixsocket.unixsocket', '');
    // Attempt to open a socket to the CloudmersiveAntivirus host and the file.
    $file_handler    = fopen($file->uri, 'r');
    $scanner_handler = @fsockopen("unix://{$unix_socket}", 0);

    // Abort if the CloudmersiveAntivirus server is unavailable.
    if (!$scanner_handler) {
      watchdog('Cloudmersive Antivirus', 'Unable to connect to CloudmersiveAntivirus daemon on unix socket @unix_socket.', array('@unix_socket' => $unix_socket), WATCHDOG_WARNING);
      return Scanner::FILE_IS_UNCHECKED;
    }

    // Push to the CloudmersiveAntivirus socket.
    $bytes = $file->getSize();
    fwrite($scanner_handler, "zINSTREAM\0");
    fwrite($scanner_handler, pack("N", $bytes));
    stream_copy_to_stream($file_handler, $scanner_handler);

    // Send a zero-length block to indicate that we're done sending file data.
    fwrite($scanner_handler, pack("N", 0));

    // Request a response from the service.
    $response = trim(fgets($scanner_handler));

    fclose($scanner_handler);

    if (preg_match('/^stream: OK$/', $response)) {
      $result = Scanner::FILE_IS_CLEAN;
    }
    elseif (preg_match('/^stream: (.*) FOUND$/', $response, $matches)) {
      $this->virusName = $matches[1];
      $result = Scanner::FILE_IS_INFECTED;
    }
    else {
      preg_match('/^stream: (.*) ERROR$/', $response, $matches);
      $result = Scanner::FILE_IS_UNCHECKED;
    }

    return $result;
  }

  /**
   * {@inheritdoc}
   */
  public function virusName() {
    return $this->virusName;
  }

  /**
   * {@inheritdoc}
   */
  public function version() {
    $unix_socket = variable_get('mode_daemon_unixsocket.unixsocket', '');
    $handler = @fsockopen("unix://{$unix_socket}", 0);
    if (!$handler) {
      watchdog('Cloudmersive Antivirus', 'Unable to connect to CloudmersiveAntivirus daemon on unix socket @unix_socket', array('@unix_socket' => $unix_socket), WATCHDOG_WARNING);
      return NULL;
    }

    fwrite($handler, "VERSION\n");
    $content = fgets($handler);
    fclose($handler);
    return $content;
  }

}
