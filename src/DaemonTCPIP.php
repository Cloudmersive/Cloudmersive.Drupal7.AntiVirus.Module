<?php

/**
 * Class of scanner item.
 */
class DaemonTCPIP {
  /**
   * The file.
   *
   * @var file
   */
  protected $file;
  /**
   * The hostname.
   *
   * @var hostname
   */
  protected $hostname;
  /**
   * The port.
   *
   * @var port
   */
  protected $port;
  /**
   * The virusname.
   *
   * @var virusname
   */
  protected $virusName = '';

  /**
   * {@inheritdoc}
   */
  public function scan($file) {

    $hostname = variable_get('mode_daemon_tcpip.hostname', '');
    $port = variable_get('mode_daemon_tcpip.port', 3310);
    // Attempt to open a socket to the CloudmersiveAntivirus host.
    $scanner_handler = @fsockopen($hostname, $port);

    // Abort if the CloudmersiveAntivirus server is unavailable.
    if (!$scanner_handler) {
      watchdog('Cloudmersive Antivirus', 'Unable to connect to Cloudmersive Antivirus TCP/IP daemon on @hostname:@port.',
        array('@hostname' => $hostname, '@port' => $port), WATCHDOG_WARNING);
      return Scanner::FILE_IS_UNCHECKED;
    }

    // Push to the CloudmersiveAntivirus socket.
    $bytes = $file->filesize;
    fwrite($scanner_handler, "zINSTREAM\0");
    fwrite($scanner_handler, pack("N", $bytes));

    // Open the file and push to the TCP/IP connection.
    $file_handler = fopen($file->uri, 'r');
    stream_copy_to_stream($file_handler, $scanner_handler);

    // Send a zero-length block to indicate that we're done sending file data.
    fwrite($scanner_handler, pack("N", 0));

    // Request a response from the service.
    $response = trim(fgets($scanner_handler));

    // Close both handlers.
    fclose($scanner_handler);
    fclose($file_handler);

    // Process the output from the stream.
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
  public static function version() {

    $hostname = variable_get('mode_daemon_tcpip.hostname', '');
    $port = variable_get('mode_daemon_tcpip.port', 3310);
    $handler = @fsockopen($hostname, $port);
    if (!$handler) {
      watchdog('Cloudmersive Antivirus', 'Unable to connect to Cloudmersive Antivirus TCP/IP daemon on @hostname:@port.',
        array('@hostname' => $hostname, '@port' => $port), WATCHDOG_WARNING);

      return NULL;
    }

    fwrite($handler, "VERSION\n");
    $content = fgets($handler);
    fclose($handler);

    return $content;
  }

}
