<?php
/*
	Plugin Name: Simple WP 2FA
	Plugin URI: https://github.com/gerharddt/
	Description: Adds simple 2FA using email to admin login.
	Version: 1.0.0
	Author: gerharddt
	Author URI: https://github.com/gerharddt/
*/

if ( ! defined( 'WPINC' ) ) {
	die;
}

// reset default timezone to wp time
date_default_timezone_set(get_option('timezone_string'));



// create db for plugin
function simple_2fa_65417823541_create_database_table() {
	global $wpdb;

	$table_name = $wpdb->prefix . 'ptcontactform';

	$charset_collate = $wpdb->get_charset_collate();


	$sql_1 = "CREATE TABLE `wp_simple_2fa_security` (
	  `id` int(11) NOT NULL,
	  `user_id` int(11) NOT NULL,
	  `simple_2fa_key` varchar(32) NOT NULL,
	  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	  `last_mailed` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

	$sql_2 = "ALTER TABLE `wp_simple_2fa_security`
	  ADD PRIMARY KEY (`id`);";

	$sql_3 = "ALTER TABLE `wp_simple_2fa_security`
	  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;";

	$result1 = $wpdb->query($sql_1);
	$result2 = $wpdb->query($sql_2);
	$result3 = $wpdb->query($sql_3);
}
register_activation_hook(__FILE__,'simple_2fa_65417823541_create_database_table');



// enqueue in header of login screen
function simple_2fa_65417823541_login_enqueue_scripts() { ?>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
<?php }
add_action( 'login_enqueue_scripts', 'simple_2fa_65417823541_login_enqueue_scripts' );


// adding to the login form
function simple_2fa_65417823541_login_form() { ?>
    <p>
		<label for="simple_2fa_security_key">Security Key</label>
		<input type="text" name="simple_2fa_security_key" id="simple_2fa_security_key" class="input" value="" size="20" autocapitalize="off">
	</p>
	<div>
		<a href="#" class="simple_2fa_request_key">Request security key</a>
		<div class="simple_2fa_error"></div>
		<div class="simple_2fa_success"></div>
	</div>

	<script>
		$('.simple_2fa_request_key').on('click', function(e) {
			e.preventDefault();

			$('.simple_2fa_success').html('');
			$('.simple_2fa_error').html('');

			var simple_2fa_user_login = $('input#user_login').val();

			if (simple_2fa_user_login) {

				$('.simple_2fa_success').html('<span>Done! Please check your email for the key.</span>');

				$.ajax({
					type: "POST",
					url: "<?php echo get_option('home'); ?>/wp-json/nfh-2fa-remote/v1/nfh-2fa-verify",
					data: { keyrequest : simple_2fa_user_login },
					dataType: "html",
					success: function (response) {
						//console.log(response);
					}
				});

			} else {
				$('.simple_2fa_error').html('<span>Please enter your Username or Email Address.</span>');
			}
		});
	</script>

	<style>

		.simple_2fa_error span {
			color: #ff0000;
			display: block;
			font-size: 11px;
			padding-top: 5px;
		}

		.simple_2fa_success span {
			color: #2aab2d;
			display: block;
			font-size: 11px;
			padding-top: 5px;
		}

	</style>

	<br><br><div class="clear:both;"></div>


<?php }
add_action( 'login_form', 'simple_2fa_65417823541_login_form' );



// post-decorator-accounts
add_action( 'rest_api_init', function () {
	register_rest_route('nfh-2fa-remote/v1', '/nfh-2fa-verify', array(
		'methods' => 'POST,GET',
		'callback' => 'simple_2fa_65417823541_verify',
		'permission_callback' => '__return_true'
	));
} );
function simple_2fa_65417823541_verify( WP_REST_Request $request ) {

	global $wpdb;

	$validKeys = array(
        'keyrequest'
    );

    $var = simple_2fa_65417823541_clean_array($_POST, $validKeys);

    $keyrequest = $var['keyrequest'];


    // check if user is valid
    $validuser = false;
    $validuserid = false;
    if ( filter_var( $keyrequest, FILTER_VALIDATE_EMAIL ) ) {
		$email_exists = email_exists( $keyrequest );
		if ( $email_exists != false ) {
			$validuser = true;
			$validuserid = $email_exists;
		}
	} else {
		$username_exists = username_exists( $keyrequest );
		if ( $username_exists != false ) {
			$validuser = true;
			$validuserid = $username_exists;
		}
	}


	// todo: check if user is admin


	if ($validuser && $validuserid) {

		$user_id = $validuserid;

		// Get the user object.
$user = get_userdata( $user_id );

// Get all the user roles as an array.
$user_roles = $user->roles;

// Check if the role you're interested in, is present in the array.
if ( in_array( 'subscriber', $user_roles, true ) ) {
    // Do something.
    echo 'YES, User is a subscriber';
}


		$tablename = $wpdb->prefix . 'simple_2fa_security';

		// if: key doesnt exist for user within 15 minute time limit
		$check_key = $wpdb->get_results( "SELECT * FROM $tablename WHERE user_id = $user_id AND timestamp > DATE_SUB(NOW(),INTERVAL 15 MINUTE) ORDER BY id DESC LIMIT 1", ARRAY_A );

		if ( isset( $check_key[0] ) ) {

			// less than 15 minutes

			$check_key_latest_id = $check_key[0]['id'];
			$check_key_latest_user_id = $check_key[0]['user_id'];
			$check_key_last_mailed = $check_key[0]['last_mailed'];
			$check_key_2fa_key = $check_key[0]['simple_2fa_key'];

			// todo - if more than 3 minutes
			if( strtotime($check_key_last_mailed) < strtotime("-3 minutes")) {

				// get user info
				$user_info = get_userdata($check_key_latest_user_id);
				$user_email = $user_info->user_email;
				$user_roles = $user->roles;

				if ( !in_array( 'administrator', $user_roles, true ) ) {
				    return;
				}

				// update timestamp
				$updated_timestamp = date('Y-m-d H:i:s');
				$time_data = array(
					'last_mailed' => $updated_timestamp
				);
				$time_where = array(
					'id' => $check_key_latest_id
				);
				$wpdb->update( $tablename, $time_data, $time_where );

				// mail key to user
				simple_2fa_65417823541_email_key($check_key_2fa_key, $user_email);

				//return 'more than 3 minutes';

			}

			//return 'less than 15 minutes';

		} else {

			// more than 15 minutes or none

			// get user info
			$user_info = get_userdata($user_id);
			$user_email = $user_info->user_email;
			$user_roles = $user->roles;

			if ( !in_array( 'administrator', $user_roles, true ) ) {
			    return;
			}

			// generate key
			$newkey = md5(time() . 'nfh2fa' . time());

			// creata db entry
			$wpdb->insert($tablename, array(
				'user_id' => $user_id,
				'simple_2fa_key' => $newkey
			));

			// mail new key to user
			simple_2fa_65417823541_email_key($newkey, $user_email);

			//return 'more than 15 minutes or none';

		}
	}
}


// validate extra field
function simple_2fa_65417823541_custom_validation($user, $password) {

	global $wpdb;

	if ( $GLOBALS['pagenow'] === 'wp-login.php' ) {

		$user_id = $user->data->ID;
		$tablename = $wpdb->prefix . 'simple_2fa_security';

		$check_key = $wpdb->get_results( "SELECT * FROM $tablename WHERE user_id = $user_id AND timestamp > DATE_SUB(NOW(),INTERVAL 15 MINUTE) ORDER BY id DESC LIMIT 1", ARRAY_A );

		if ( isset( $check_key[0] ) ) {

			// less than 15 minutes
			$check_key_2fa_key = $check_key[0]['simple_2fa_key'];

			if ( trim($check_key_2fa_key) != trim($_POST['simple_2fa_security_key']) ) {

				remove_action('authenticate', 'wp_authenticate_username_password', 20);
	        	$user = new WP_Error( 'denied', __("<strong>ERROR</strong>: Please check your security key and try again.") );

			}

		} else {

			remove_action('authenticate', 'wp_authenticate_username_password', 20);
	        $user = new WP_Error( 'denied', __("<strong>ERROR</strong>: Your security key has expired.") );

		}

	} else {

		$user_roles = $user->roles;

		if ( in_array( 'administrator', $user_roles, true ) ) {

			remove_action('authenticate', 'wp_authenticate_username_password', 20);
			$user = new WP_Error( 'denied', __("<strong>ERROR</strong>: Please log in on the admin login page.") );

		}
	}

	return $user;

}
add_filter( 'wp_authenticate_user', 'simple_2fa_65417823541_custom_validation', 10, 3 );



// helpers


function simple_2fa_65417823541_email_key($key,$email) {
	wp_mail( $email, 'Your ' . get_bloginfo('name') . ' security key! :)', $key );
}


// clean array
function simple_2fa_65417823541_clean_array($arr, $valid = null) {

	$return = array();

	foreach ( $arr as $key => $value ) {
		if ( !is_null($valid) && is_array($valid) && !in_array($key, $valid) ) {
			continue;
		}
		$return[$key] = addslashes(trim(strip_tags(stripslashes($value))));
	}
	return $return;

}




















// function simple_2fa_65417823541_login_message() { ? >
//     testing two
// <?php }
//add_action( 'login_message', 'simple_2fa_65417823541_login_message' );








// // create db



// // hook for JS


// // add extra field and html/js

// // validate 3rd field on login form

// // after validated hook, add validation checking for valid key

// from user.php unde wp-includes
/**
 * Filters whether the given user can be authenticated with the provided $password.
 *
 * @since 2.5.0
 *
 * @param WP_User|WP_Error $user     WP_User or WP_Error object if a previous
 *                                   callback failed authentication.
 * @param string           $password Password to check against the user.
 */
// $user = apply_filters( 'wp_authenticate_user', $user, $password );
// if ( is_wp_error( $user ) ) {
// 	return $user;
// }