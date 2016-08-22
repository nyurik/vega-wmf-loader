( function ( $, vg ) {

	'use strict';
	/* global require */

	var wrapper,
		VegaWrapper = require( 'graph-shared' ),
		urlParse = require( 'url-parse' );

	wrapper = new VegaWrapper(
		vg.util.load, true,
		false,
		{
			'https': [
				'mediawiki.org',
				'wikibooks.org',
				'wikidata.org',
				'wikimedia.org',
				'wikimediafoundation.org',
				'wikinews.org',
				'wikipedia.org',
				'wikiquote.org',
				'wikisource.org',
				'wikiversity.org',
				'wikivoyage.org',
				'wiktionary.org',
			],
			'http': [ // optional
				'wmflabs.org',
			],
			'wikirawupload': [
				'upload.wikimedia.org',
				'upload.beta.wmflabs.org', // optional
			],
			'wikidatasparql': [
				'query.wikidata.org',
				'wdqs-test.wmflabs.org', // optional
			],
			'geoshape': [
				'maps.wikimedia.org',
			]
		},
		false,
		function ( warning ) {
			console.log( warning );
		}, $.extend, function ( opt ) {
			// Parse URL
			var uri = urlParse( opt.url, true );
			// reduce confusion, only keep expected values
			delete uri.port;
			// If url begins with   protocol:///...  mark it as having relative host
			if ( /^[a-z]+:\/\/\//.test( opt.url ) ) {
				uri.isRelativeHost = true;
			}
			if (uri.protocol && uri.protocol[uri.protocol.length - 1] === ':') {
				uri.protocol = uri.protocol.substring(0, uri.protocol.length - 1);
			}
			return uri;
		}, function ( uri, opt ) {
			// Format URL back into a string
			if ( location.host.toLowerCase() === uri.host.toLowerCase() ) {
				// Only send this header when hostname is the same.
				// This is broader than the same-origin policy,
				// but playing on the safer side.
				opt.headers = { 'Treat-as-Untrusted': 1 };
			} else if ( opt.addCorsOrigin ) {
				// All CORS api calls require origin parameter.
				// It would be better to use location.origin,
				// but apparently it's not universal yet.
				uri.query.origin = location.protocol + '//' + location.host;
			}

			return uri.toString();
		} );

}( jQuery, vg ) );
