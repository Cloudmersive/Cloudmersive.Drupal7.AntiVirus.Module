<?php

/**
 * Class of scanner item.
 */
class Executable {
  /**
   * The Executable path.
   *
   * @var executablepath
   */
  private $executablePath = '';
  /**
   * The Executable parameters.
   *
   * @var executableparameters
   */
  private $executableParameters = '';
  /**
   * The file.
   *
   * @var file
   */
  private $file = '';
  /**
   * The virus Name.
   *
   * @var virusname
   */
  protected $virusName = '';

  /**
   * {@inheritdoc}
   */
  public function scan($file) {

    $executable_path = variable_get('mode_executable.executable_path', '');
    $executable_parameters = variable_get('mode_executable.executable_parameters', '');
    $script = "{$executable_path} {$executable_parameters}";
    $filename = drupal_realpath($file->uri);
    $cmd = escapeshellcmd($script) . ' ' . escapeshellarg($filename) . ' 2>&1';
    $timeout = variable_get('curl_timeout_value', 30);

    $curl = curl_init();

    $key = $executable_path;

    curl_setopt_array($curl, array(
      CURLOPT_URL => "https://api.cloudmersive.com/virus/scan/file",
      CURLOPT_RETURNTRANSFER => TRUE,
      CURLOPT_ENCODING => "",
      CURLOPT_MAXREDIRS => 10,
      CURLOPT_TIMEOUT => $timeout,
      CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
      CURLOPT_CUSTOMREQUEST => "POST",
      CURLOPT_HTTPHEADER => array(
        "cache-control: no-cache",
        "Apikey: " . $key,
        "content-type: application/x-www-form-urlencoded",
      ),
      CURLOPT_POSTFIELDS => array(
        'inputFile' => new \CURLFile($filename),
      ),
    ));

    $response = curl_exec($curl);
    $err = curl_error($curl);

    curl_close($curl);
    $strResponse = (string) $response;

    if (strpos($strResponse, '"CleanResult":true') !== FALSE) {
      return Scanner::FILE_IS_CLEAN;
    }
    else {
      return Scanner::FILE_IS_INFECTED;
    }
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

    return "1";

  }

}
