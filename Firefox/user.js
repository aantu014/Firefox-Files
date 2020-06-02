// Mozilla User Preferences

// 
//
// If you make changes to this file while the application is running,
// the changes will be overwritten when the application exits.
//
// To change a preference value, you can either:
// - modify it via the UI (e.g. via about:config in the browser); or
// - set it within a user.js file in your profile.

//user_pref("browser.safebrowsing.downloads.remote.enabled", false); //More privacy but less security when downloading shit. STRONGLY NOT RECOMMENDED
// user_pref("browser.safebrowsing.malware.enabled", false); //More privacy but less security  STRONGLY NOT RECOMMENDED
// user_pref("browser.safebrowsing.phishing.enabled", false); //More privacy but less security  STRONGLY NOT RECOMMENDED
/*Prevents Firefox from sending information about downloaded executable files to Google Safe Browsing.*/
user_pref("browser.safebrowsing.provider.google.advisoryURL", "");
user_pref("browser.safebrowsing.provider.google.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportURL", "");
user_pref("browser.safebrowsing.provider.google4.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportURL", "");
user_pref("browser.safebrowsing.reportPhishURL", "");

//If connecting to public wifi asking for Terms of Service might not be able to connect.
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);

user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("dom.popup_allowed_events", "click");

//Will break video player fonts
//user_pref("gfx.downloadable_fonts.enabled", false);
//user_pref("gfx.downloadable_fonts.fallback_delay", -1);

//will make fonts look ugly
user_pref("gfx.downloadable_fonts.disable_cache", true);
user_pref("gfx.font_rendering.graphite.enabled", false);
user_pref("gfx.font_rendering.opentype_svg.enabled", false);

//Wont allow website notification
user_pref("dom.push.connection.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("dom.webnotifications.enable", false);
user_pref("dom.webnotifications.serviceworker.enabled", false);

//Disabling Ion/JIT can cause some site issues and performance loss
// user_pref("javascript.options.ion", false);
// user_pref("javascript.options.baselinejit", false);

user_pref("dom.IntersectionObserver.enabled", false);
user_pref("dom.popup_maximum", 5);
user_pref("privacy.spoof_english", 2);
user_pref("dom.webaudio.enabled", false);
user_pref("security.family_safety.mod", 0);
user_pref("dom.enable_performance_navigation_timing", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.available", "off");
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.firstTimeUse", false);
user_pref("extensions.formautofill.heuristics.enabled", false);
user_pref("extensions.getAddons.cache.enabled", false);
user_pref("extensions.screenshots.disabled", true);
user_pref("dom.gamepad.enabled", false);
user_pref("media.video_stats.enabled", false);
user_pref("media.ondevicechange.enabled", false);
user_pref("browser.library.activity-stream.enabled", false);
user_pref("dom.serviceWorkers.enabled", false);//Could break sites
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);
user_pref("dom.ipc.plugins.reportCrashURL", false);
user_pref("media.getusermedia.screensharing.enabled", false);
user_pref("security.mixed_content.block_display_content", true);
user_pref("security.mixed_content.block_object_subrequest", true);
user_pref("security.OCSP.require", true);
user_pref("security.cert_pinning.enforcement_level",2);
user_pref("accessibility.force_disabled", 1);
user_pref("accessibility.typeaheadfind.flashBar", 0);
user_pref("app.normandy.first_run", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("beacon.enabled", false);
user_pref("browser.aboutConfig.showWarning", false);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk_cache_ssl", false);
user_pref("browser.cache.offline.enable", false);
user_pref("browser.cache.offline.storage.enable", false);
user_pref("browser.contentblocking.category", "custom");
user_pref("browser.ctrlTab.recentlyUsedOrder", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.download.hide_plugins_without_extensions", false);
user_pref("browser.formfill.enable", false);
//user_pref("browser.launcherProcess.enabled", true); Windows
user_pref("browser.link.open_newwindow.restriction", 0);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.asrouter.providers.snippets", "");
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.searchEngines", "");
user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");
user_pref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeDownloads", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeVisited", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry.structuredIngestion", false);
user_pref("browser.newtabpage.storageVersion", 1);
user_pref("browser.pagethumbnails.storage_version", 3);
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.privatebrowsing.autostart", true);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.search.update", false);
user_pref("browser.send_pings.require_same_host", true);
//user_pref("browser.sessionstore.interval", 3600000);// reduce writes on drive
user_pref("browser.sessionhistory.max_entries", 5);
user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.shell.didSkipDefaultBrowserCheckOnFirstRun", true);
//user_pref("browser.tabs.remote.autostart", false); //will reduce ram usage but reduce perfomance
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.taskbar.lists.frequent.enabled", false);
user_pref("browser.touchmode.auto", false);
user_pref("dom.w3c_touch_events.enabled", 0);
user_pref("browser.uidensity", 1);
user_pref("browser.urlbar.autoFill", false);
user_pref("browser.urlbar.oneOffSearches", false);
user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
user_pref("browser.urlbar.placeholderName.private", "DuckDuckGo");
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.urlbar.suggest.bookmark", false);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", "");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionPolicyAcceptedVersion", 2);
user_pref("device.sensors.enabled", false);
user_pref("distribution.iniFile.exists.value", false);
user_pref("doh-rollout.balrog-migration-done", true);
user_pref("dom.battery.enabled", false);
user_pref("dom.enable_performance", false);
user_pref("dom.enable_resource_timing", false);
user_pref("dom.event.clipboardevents.enabled", false); //Breaks copy/paste function on JS-based web applications like Google Docs.
user_pref("dom.event.contextmenu.enabled", false);//Breaks right-click function on JS-based web applications like Google Docs.
user_pref("dom.events.asyncClipboard", false);
user_pref("dom.forms.autocomplete.formautofill", false);
user_pref("dom.vr.enabled", false);
user_pref("dom.vibrator.enabled", false);
//user_pref("dom.ipc.processCount", 1);                     //Might cause performance dips
user_pref("extensions.pocket.enabled", false);
user_pref("font.internaluseonly.changed", false);
user_pref("general.autoScroll", false);
user_pref("general.smoothScroll", false);
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
user_pref("geo.provider.ms-windows-location", false); // [WINDOWS]
//user_pref("geo.provider.use_corelocation", false); // [MAC]
//user_pref("geo.provider.use_gpsd", false); // [LINUX]
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("browser.search.geoSpecificDefaults.url", "");
user_pref("javascript.options.asmjs", false);
//user_pref("javascript.options.wasm", false);  //breaks crunchyroll subs
user_pref("layout.css.visited_links_enabled", false);
user_pref("layers.mlgpu.sanity-test-failed", false);
user_pref("layout.spellcheckDefault", 0);
user_pref("mathml.disabled", true);
user_pref("media.autoplay.default", 0);
//user_pref("media.eme.enabled", false);  //Wont be able to watch watch Netflix nor Crunchyroll
//user_pref("media.gmp-widevinecdm.enabled", false); //Wont be able to watch watch Netflix nor Crunchyroll
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp.storage.version.observed", 1);
user_pref("media.hardware-video-decoding.failed", false);
user_pref("media.navigator.enabled", false);
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.identity.enabled", false);
user_pref("media.peerconnection.identity.timeout", 1);
user_pref("media.peerconnection.turn.disable", true);
user_pref("media.peerconnection.use_document_iceservers", false);
user_pref("media.peerconnection.video.enabled", false);
user_pref("media.videocontrols.picture-in-picture.video-toggle.enabled", false);
user_pref("media.webspeech.synth.enabled", false);
user_pref("media.wmf.deblacklisting-for-telemetry-in-gpu-process", false);
user_pref("network.auth.subresource-http-auth-allow", 0); // Might break change to 1
user_pref("network.IDN_show_punycode", true);
user_pref("network.connectivity-service.enabled", false);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.ftp.enabled", false);
user_pref("network.http.max-persistent-connections-per-server", 10);
user_pref("network.http.referer.XOriginPolicy", 1); // Setting to 2 breaks sites
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("network.http.referer.trimmingPolicy", 2);
//user_pref("network.http.referer.spoofSource", true); // Breaks sites
//user_pref("network.http.sendRefererHeader", 0); // Breaks sites
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.predictor.cleaned-up", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.protocol-handler.external.ms-windows-store", false);
user_pref("network.protocol-handler.external.news", false);
user_pref("network.protocol-handler.external.nntp", false);
user_pref("network.protocol-handler.external.mailto", false);
user_pref("network.protocol-handler.external.snews", false);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.security.esni.enabled", true);
user_pref("network.trr.bootstrapAddress", "1.1.1.1");
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");
user_pref("permissions.default.camera", 2);
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.geo", 2);
user_pref("permissions.default.microphone", 2);
user_pref("permissions.delegation.enabled", false);
user_pref("places.history.enabled", false);
user_pref("plugin.mousewheel.enabled", false);
user_pref("plugin.scan.plid.all", false);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.siteSettings", true);
user_pref("privacy.cpd.offlineApps", true);
user_pref("privacy.cpd.passwords", true);
user_pref("privacy.cpd.siteSettings", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.history.custom", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.sanitize.migrateFx3Prefs", true);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.sanitize.timeSpan", 0);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("sanity-test.advanced-layers", true);
user_pref("sanity-test.running", false);
user_pref("security.certerrors.recordEventTelemetry", false);
user_pref("security.identitypopup.recordEventTelemetry", false);
user_pref("security.pki.sha1_enforcement_level", 1);
user_pref("security.protectionspopup.recordEventTelemetry", false);
user_pref("security.ssl.enable_false_start", false);
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("security.ssl3.rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_aes_128_sha", false);
user_pref("security.ssl3.rsa_aes_256_sha", false);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.tls.version.min", 3);
user_pref("services.sync.globalScore", 0);
user_pref("services.sync.nextSync", 0);
user_pref("services.sync.tabs.lastSync", "0");
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.generation.enabled", false);
user_pref("signon.management.page.breach-alerts.enabled", false);
user_pref("signon.rememberSignons", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.hybridContent.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
//Disable any other "telemetry" and anything with "report" in about:config
user_pref("ui.osk.enabled", false);
user_pref("webgl.enable-debug-renderer-info", false);
user_pref("webgl.disabled", true);

////test These out
user_pref("browser.geolocation.warning.infoURL", "");
user_pref("browser.search.region", "");

user_pref("identity.fxaccounts.remote.profile.uri", "");
user_pref("identity.mobilepromo.android", "");
//user_pref("identity.mobile.promo", ""); //depreacted?
user_pref("identity.mobilepromo.ios", "");
user_pref("layers.shared-buffer-provider.enabled", false);
user_pref("security.sandbox.logging.enabled", false);
user_pref("toolkit.cosmeticAnimations.enabled", false);

//If first party isolate is enabled but makes shit slow af
//user_pref("network.http.altsvc.enabled", false);
//user_pref("network.http.altsvc.oe", false);

user_pref("dom.indexedDB.logging.details", false);
user_pref("dom.indexedDB.logging.enabled", false);
 
//user_pref("dom.caches.enabled", false); might affect perfomance
