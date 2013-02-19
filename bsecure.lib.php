<?PHP
  class BSecure
  {
    private $bs_info = array(
                'base' => array('host' => 'localhost',
                                'database' => 'bsecure',
                                'logout' => 'bsecure.log',
                                'logfile' => null),
                'users' => array('bsu_newuser' => array('username' => 'bsu_newuser',
                                                        'password' => '',
                                                        'link' => null),
                                 'bsu_auth' => array('username' => 'bsu_auth',
                                                     'password' => '',
                                                     'link' => null)
                                ),
                'filters' => array('alphanumeric' => '[^a-zA-Z0-9\\.]'),
                'queries' => array('CreateUser' => 'INSERT INTO `bst_users`(`username`, `password`) VALUES(\'%s\', \'%s\')',
                                   'CheckCredentials' => 'SELECT `uid` FROM `bst_users` WHERE `bst_users`.`username` = \'%s\' AND `bst_users`.`password` = \'%s\'',
                                   'Logoff' => 'DELETE FROM `bst_online` WHERE `ip` = \'%s\' AND `fingerprint` = \'%s\'',
                                   'IsAuth' => 'SELECT `uid` FROM `bst_online` WHERE `ip` = \'%s\' AND `fingerprint` = \'%s\'',
                                   'SetAuth' => 'INSERT INTO `bst_online` (`uid`, `ip`, `fingerprint`) VALUES(\'%s\', \'%s\', \'%s\')')
                            );

    public function __construct()
    {
      $this->bs_info['base']['logfile'] = fopen($this->bs_info['base']['logout'], 'a');
      foreach($this->bs_info['users'] as &$val)
      {
        $val['link'] = new mysqli($this->bs_info['base']['host'], $val['username'], $val['password'], $this->bs_info['base']['database']);
        
        if ($val['link']->connect_error)
        {
          $this->LogMsg('ConnErr', '('.$val['link']->connect_errno.') '.$var['link']->connect_error);
        }
      }
    }
    
    public function __destruct()
    {
      foreach($this->bs_info['users'] as &$val)
      {
        $val['link']->close();
      }
      fclose($this->bs_info['base']['logfile']);
    }
    
    private function LogMsg($type, $msg)
    {
      fwrite($this->bs_info['base']['logfile'], '['.date('Ymd H:i:s').'] '.$type.' : '.$msg);
    }
    
    /**
     * @brief This function runs all queries through a filter.
     *
     * @param[in] userInput Array of user inputs, in order of occurance for $this->['queries'][$string]
     * @param[in] allowedChars A regular expression set of characters allowed, but inverted. Lowercase characters would appear as such. [^a-z]
     * @param[in] dbuser The username of the database user that will be preforming this operation.
     * @param[in] queryString The name of the query string in $this->['queries'][$queryString]
     *
     * @retval FALSE on failure
     * @retval SELECT For successful SELECT queries mysqli_query() will return a mysqli_result object.
     * @retval SHOW For successful SHOW queries mysqli_query() will return a mysqli_result object.
     * @retval DESCRIBE For successful DESCRIBE queries mysqli_query() will return a mysqli_result object.
     * @retval EXPLAIN For successful EXPLAIN queries mysqli_query() will return a mysqli_result object.
     * @retval TRUE For other successful queries mysqli_query() will return TRUE.
     */
    
    private function Query($userInput, $allowedChars, $dbuser, $queryString)
    {
      $rVal = FALSE;
      
      if (is_array($userInput))
      {
        if (empty($allowedChars))
        {
          $allowedChars = $this->bs_info['filters']['alphanumeric'];
        }
        
        foreach ($userInput as $key => $val)
        {
          $userInput[$key] = preg_replace($allowedChars, '', $val);
        }
        
        $rVal = $this->bs_info['users'][$dbuser]['link']->query(vsprintf($this->bs_info['queries'][$queryString], $userInput));
      }      
      
      return ($rVal);
    }

    /**
     * @brief Generates a weak fingerprint of the client. More information here https://panopticlick.eff.org/
     *
     * @retval sh256 hash of the $_SERVER['HTTP_USER_AGENT'] and $_SERVER['HTTP_ACCEPT'] variables
     */
    private function FingerPrint()
    {
      return (hash('sha256', $_SERVER['HTTP_USER_AGENT'].$_SERVER['HTTP_ACCEPT']));
    }

    /**
     * @brief Creates a new user in the `bst_users` table.
     *
     * @param[in] username String representing the desired username of the user to be created.
     * @param[in] password String representing the plain text password desired for the new user.
     *
     * @retval TRUE if a new user is created.
     * @retval FALSE if the new user is not created.
     */
    public function CreateUser($username, $password)
    {
      $rVal = TRUE;
      $input = array($username, hash('sha256', $password));
      if (!($this->Query($input, null, 'bsu_newuser', 'CreateUser')))
      {
        $this->LogMsg('CreateUserErr', $this->bs_info['users']['bsu_newuser']['link']->error);
        $rVal = FALSE;
      }
      return ($rVal);
    }

    /**
     * @brief Attempts to log the specified user in by adding them to the `bst_online` table.
     *
     * @param[in] username String representing the username of the user to be logged in.
     * @param[in] password String representing the plain text password of the user to be logged in.
     *
     * @retval TRUE if a user is logged in.
     * @retval FALSE if the user is not logged in.
     */
    public function Logon($username, $password)
    {
      $rVal = TRUE;
      $input = array($username, hash('sha256', $password));
      if ($result =$this->Query($input, null, 'bsu_auth', 'CheckCredentials'))
      {
        $uid = $result->fetch_object()->uid;
        $result->close();
        $input = array($uid, $_SERVER['REMOTE_ADDR'], $this->FingerPrint());
        if (!($this->Query($input, null, 'bsu_auth', 'SetAuth')))
        {
          $this->LogMsg('SetAuthErr', $this->bs_info['users']['bsu_auth']['link']->error);
          $rVal = FALSE;
        }
      }
      else
      {
        $this->LogMsg('CheckCredentialsErr', $this->bs_info['users']['bsu_auth']['link']->error);
        $rVal = FALSE;
      }
      return ($rVal);
    }

    /**
     * @brief Logoff the user at the current IP address.
     *
     * @retval TRUE if logoff succeeds.
     * @retval FALSE if logoff fails.
     */
    public function Logoff()
    {
      $rVal = TRUE;
      $input = array($_SERVER['REMOTE_ADDR'], $this->FingerPrint());
      if (!($this->Query($input, null, 'bsu_auth', 'Logoff')))
      {
        $this->LogMsg('LogoffErr', $this->bs_info['users']['bsu_auth']['link']->error);
        $rVal = FALSE;
      }
      return ($rVal);
    }

    /**
     * @brief Attempts to authenticate client against the `bst_online` table.
     *
     * @retval TRUE if authentication is successful.
     * @retval FALSE if authentication is a failure.
     */
    public function Auth()
    {
      $uid = null;
      $input = array($_SERVER['REMOTE_ADDR'], $this->FingerPrint());
      if ($result = $this->Query($input, null, 'bsu_auth', 'IsAuth'))
      {
        $uid = $result->fetch_object()->uid;
        $result->close();
      }
      return ($uid);
    }
  };
?>
