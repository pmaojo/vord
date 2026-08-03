<?php
/**
 * Plugin Name: Vord Vulnerable Demo
 * Description: Intentionally insecure fixture used by vord's own test suite.
 * Every finding this file trips is expected by fixtures/.ground-truth.json
 * and asserted by bin/cli/tests/scan_fixtures.rs — see fixtures/wordpress_clean.php
 * for the same plugin written the WPCS-approved way.
 */

function vord_demo_save_settings() {
	// wordpress:nonce-verification-missing — no wp_verify_nonce()/check_admin_referer() anywhere in this function.
	update_option( 'vord_demo_option', $_POST['value'] );
}
add_action( 'admin_post_vord_demo_save', 'vord_demo_save_settings' );

function vord_demo_render_greeting() {
	// wordpress:unescaped-superglobal-output
	echo $_GET['name'];
}

function vord_demo_store_email() {
	// wordpress:unsanitized-superglobal-input
	$email = $_POST['email'];
	return $email;
}

function vord_demo_recent_posts_by_author( $author_id ) {
	global $wpdb;
	// wordpress:unprepared-wpdb-query
	return $wpdb->get_results( "SELECT * FROM wp_posts WHERE post_author = " . $author_id );
}

function vord_demo_notice() {
	// wordpress:i18n-missing-text-domain — missing the text-domain argument.
	return __( 'Settings saved' );
}

function vord_demo_legacy_query() {
	// wordpress:discouraged-function — query_posts() clobbers the main query.
	query_posts( 'category_name=news' );
}

function vord_demo_redirect_after_login() {
	// wordpress:discouraged-function — wp_redirect() skips allowed-host validation.
	wp_redirect( $_GET['redirect_to'] );
}

function vord_demo_reset_post( $replacement ) {
	global $post;
	// wordpress:global-variable-override
	$post = $replacement;
}

// wordpress:global-variable-override — clobbers $wpdb for every other piece of code in the request.
$GLOBALS['wpdb'] = null;

function vord_demo_admin_menu() {
	// wordpress:unsafe-plugin-menu-slug
	add_menu_page( 'Vord Demo', 'Vord Demo', 'manage_options', $_GET['page'], 'vord_demo_render_page' );
}
add_action( 'admin_menu', 'vord_demo_admin_menu' );

function vord_demo_enqueue_assets() {
	// wordpress:unversioned-enqueued-resource — missing $ver argument.
	wp_enqueue_script( 'vord-demo', plugins_url( 'app.js', __FILE__ ) );
}
add_action( 'wp_enqueue_scripts', 'vord_demo_enqueue_assets' );

function vord_demo_theme_dir() {
	// wordpress:discouraged-constant
	return TEMPLATEPATH;
}

function vord_demo_maybe_process() {
	// wordpress:assignment-in-condition — likely a typo for ==.
	if ( $should_process = false ) {
		vord_demo_legacy_query();
	}
}
