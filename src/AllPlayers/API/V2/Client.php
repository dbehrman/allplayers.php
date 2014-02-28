<?php

namespace AllPlayers\V2;

use AllPlayers\Component\HttpClient;

class Client extends HttpClient
{
    /**
     * The default APCI agent.
     */
    const APCI = 'apci';

    /**
     * The user attempting to authenticate.
     *
     * @var integer
     */
    protected $user;

    /**
     * The private key content.
     *
     * @var string
     */
    protected $privateKey;

    /**
     * Create a new client to the API v2 Server.
     *
     * @param int $user
     *   The uid of the user to connect as.
     * @param string $agent
     *   The the name of the key to use for HMAC.
     */
    public function __construct($user = 0, $agent = self::APCI)
    {
        $base_url = variable_get('apci_api_internal');
        parent::__construct($base_url);

        $key_file = __DIR__ . '/keys/' . $agent . '.key';
        if (file_exists($key_file)) {
            $this->agent = $agent;
            $this->user = $user;
            $this->privateKey = file_get_contents($key_file);
        }
    }

    /**
     * Send the data to the api server with an HMAC.
     *
     * @param string $path
     *   The path of the url to call.
     * @param array $data
     *   The data to include.
     *
     * @return array|stdClass
     *   Array or object from decodeResponse().
     */
    public function post($path, $data)
    {
        $data = base64_encode(json_encode($data));
        $hmac = null;
        openssl_private_encrypt(hash('sha256', $data), $hmac, $this->privateKey);
        $post_data = array(
            'data' => $data,
            'hmac' => base64_encode($hmac),
            'user' => $this->user,
            'agent' => $this->agent,
        );

        return $this->httpRequest('POST', $path, null, $post_data, null);
    }

    /**
     * Create a hashed version of the session id.
     *
     * @return string
     *   A hashed token.
     */
    public static function tokenizeSession()
    {
        return hash('sha256', session_id());
    }
}
