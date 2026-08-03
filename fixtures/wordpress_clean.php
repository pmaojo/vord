<?php
/**
 * Plugin Name: Vord Clean Demo
 * Description: The same plugin as fixtures/wordpress_vulnerable.php, written
 * the WPCS-approved way — proves the wordpress:* ruleset's findings come
 * from the specific patterns in that file, not from WordPress/PHP code in
 * general.
 */

function vord_clean_save_settings() {
	if ( ! isset( $_POST['vord_clean_nonce'] )
		|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['vord_clean_nonce'] ) ), 'vord_clean_save' ) ) {
		return;
	}
	$value = sanitize_text_field( wp_unslash( $_POST['value'] ) );
	update_option( 'vord_clean_option', $value );
}
add_action( 'admin_post_vord_clean_save', 'vord_clean_save_settings' );

function vord_clean_render_greeting() {
	check_admin_referer( 'vord_clean_greeting' );
	$name = isset( $_GET['name'] ) ? sanitize_text_field( wp_unslash( $_GET['name'] ) ) : '';
	echo esc_html( $name );
}

function vord_clean_store_email() {
	check_admin_referer( 'vord_clean_store_email' );
	$email = sanitize_email( wp_unslash( $_POST['email'] ) );
	return $email;
}

function vord_clean_recent_posts_by_author( $author_id ) {
	global $wpdb;
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE post_author = %d", $author_id ) );
}

function vord_clean_notice() {
	return __( 'Settings saved', 'vord-clean-demo' );
}

function vord_clean_query_recent_posts() {
	return new WP_Query( array( 'category_name' => 'news' ) );
}

function vord_clean_redirect_after_login( $target ) {
	wp_safe_redirect( $target );
	exit;
}

function vord_clean_get_current_post() {
	global $post;
	return $post;
}

function vord_clean_admin_menu() {
	add_menu_page( 'Vord Demo', 'Vord Demo', 'manage_options', 'vord-clean-demo', 'vord_clean_render_page' );
}
add_action( 'admin_menu', 'vord_clean_admin_menu' );

function vord_clean_enqueue_assets() {
	wp_enqueue_script( 'vord-clean-demo', plugins_url( 'app.js', __FILE__ ), array(), '1.0.0', true );
}
add_action( 'wp_enqueue_scripts', 'vord_clean_enqueue_assets' );

function vord_clean_theme_dir() {
	return get_template_directory();
}

function vord_clean_maybe_process( $should_process ) {
	if ( $should_process === true ) {
		vord_clean_query_recent_posts();
	}
}
