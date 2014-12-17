<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

$plugin_info = array(
		'pi_name'         => 'Location Sniffing',
		'pi_version'      => '1.0',
		'pi_author'       => 'Louis Dekeister (Hop Studios)',
		'pi_author_url'   => 'http://hopstudios.com/',
		'pi_description'  => 'Returns a list of site members',
		'pi_usage'        => Hop_location_sniffing::usage()
	);

class Hop_location_sniffing {

	private $tag_content = "";
	
	public $return_data = "";
	
    public function __construct()
    {
		//Load IP to nation stuff
		ee()->load->model('ip_to_nation_data', 'ip_data');
		
		include PATH_THIRD.'hop_location_sniffing/locales.php';
		
		//Get tag content
		$this->tag_content = ee()->TMPL->tagdata;
		
		$parameter = ee()->TMPL->fetch_param('rule');
		
		$params = explode('|', $parameter);
		
		$country_code = $this->_get_country_from_ip();
		
		//We stop here
		if ($country_code === FALSE)return;
		
		 $country_code = strtoupper($country_code);
		
		//Parse the list of parameters
		//As it's only "OR" operators, when we can validate one parameter, we stop the script there
		foreach ($params as $param)
		{
			//Hanle "not .." rules
			if (substr($param, 0, 4) == "not ")
			{
				$not = TRUE;
				$param = substr($param, 4);
			}
			else
			{
				$not = FALSE;
			}
			
			if (
				(strtoupper($param) == $country_code && !$not)
				|| (strtoupper($param) != $country_code && $not) 
			)
			{
				//country is in parameters list
				$this->return_data = $this->tag_content;
				return;
			}
			else if ($param == "@eurozone") //param is eurozone
			{
				if (
					(array_search($country_code, $eurozone) !== FALSE && !$not)
					|| (array_search($country_code, $eurozone) === FALSE && $not)
				)
				{
					//current country is in Eurozone
					$this->return_data = $this->tag_content;
					return;
				}
			}
			else if ($param == "@europa") //param is European Union
			{
				if (
					(array_search($country_code, $europa) !== FALSE && !$not)
					|| (array_search($country_code, $europa) === FALSE && $not)
				)
				{
					//current country is in European Union
					$this->return_data = $this->tag_content;
					return;
				}
			}
			else if (substr($param, 0, 1) == "@") //param is a continent
			{
				
				$continent_code = strtoupper(substr($param, 1, 2));
				
				if (array_key_exists($country_code, $countries_continent))
				{
					
					if (
						($countries_continent[$country_code] == $continent_code && !$not)
						|| ($countries_continent[$country_code] != $continent_code && $not)
					)
					{
						$this->return_data = $this->tag_content;
						return;
					}
				}
			}
		}
    }
	
	
	private function _get_country_from_ip()
	{
		$ip = ee()->input->ip_address();
		//$ip = '186.34.23.43';		//Chile
		//$ip = '116.34.23.43';		//South Korea
		//$ip = '126.34.23.43';		//Japan
		//$ip = '188.121.62.155';	//Netherlands
		//$ip = '196.201.216.171';	//Kenya
		//$ip = '212.76.87.188';	//Saudi Arabia
		//$ip = '148.251.234.73';	//Germany
		//$ip = '62.103.107.9';		//Greece
		//$ip = '213.181.73.145';	//Spain 
		//$ip = '178.116.172.83';	//Belgium
		//$ip = '128.199.206.219'; 	//Singapore
		$ip = '81.23.54.122'; 	//Great Britain
		//$ip = '5.28.16.3';		//Russia
		//echo $ip;
		
		if (ee()->input->valid_ip($ip))
		{
			$c_code = ee()->ip_data->find($ip);

			if ($c_code === FALSE)
			{
				return FALSE;
			}
			return $c_code;
		}
		else
		{
			return FALSE;
		}
	}
	
	
	public static function usage()
	{
		ob_start();  ?>

The Location Sniffing plugin from Hop Studios

    {exp:hop_location_sniffing rule="@EU"}only visible if IP = european country{/exp:hop_location_sniffing}

Available rules :
---------------------
- continents : @AF, @EU, @AS, @NA, @SA, @AN, @OC

- countries : the whole list is available on Wikipedia http://en.wikipedia.org/wiki/ISO_3166-1 (use alpha-2 code)

- European Union : http://en.wikipedia.org/wiki/European_Union @europa

- Eurozone : http://en.wikipedia.org/wiki/Eurozone (euro currency) @eurozone


You can create lists of rules just as in exp:channel:entries tags : fr|de|be|gb|@AF

You can add "not " in front of a rule, just as in exp:channel:entries : @EU|not US
    <?php
        $buffer = ob_get_contents();
        ob_end_clean();

        return $buffer;
	}
	
}