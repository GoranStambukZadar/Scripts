// Ads-Blocking Proxy Auto-Configuration (PAC) File
// Author: Gorstak

// Configuration Variables
var normal = "DIRECT";              // Default pass-through for non-blocked traffic
var blackhole = "PROXY 127.0.0.1:3421"; // Blackhole proxy for blocked traffic
var isEnabled = 1;                  // Toggle for enabling/disabling ad-blocking (1 = enabled)
var debug = 0;                      // Debugging flag (1 = enabled)

// Whitelist: Domains explicitly allowed, bypassing all filters
var whitelist = [
    "twitter.com",
    "x.com",
    "perplexity.ai",
    "mediafire.com",
    "apple.com",
    "schooner.com",
    "citibank.com",
    "ebay.com",
    "yahoo.com",
    "discord.com",
    "click.discord.com",
    "discordapp.com",
    "cdn.discordapp.com",
    "cdn.discord.app",
    "discord.gg",
    "discord.media",
    "discordapp.net",
    "media.discordapp.net",
    "discordstatus.com",
    "dis.gd",
    "discordcdn.com",
    "aliexpress.com",
    "tenor.com",
    "media.tenor.com"
];

// Comprehensive Regular Expression for Ad/Tracking Domains and Subdomains
var adDomainRegex = /^(?:.*[-_.])?(ads?|adv(ert(s|ising)?)?|banners?|track(er|ing|s)?|beacons?|doubleclick|adservice|adnxs|adtech|googleads|gads|adwords|partner|sponsor(ed)?|click(s|bank|tale|through)?|pop(up|under)s?|promo(tion)?|market(ing|er)?|affiliates?|metrics?|stat(s|counter|istics)?|analytics?|pixel(s)?|campaign|traff(ic|iq)|monetize|syndicat(e|ion)|revenue|yield|impress(ion)?s?|conver(sion|t)?|audience|target(ing)?|behavior|profil(e|ing)|telemetry|survey|poll|outbrain|taboola|quantcast|scorecard|omniture|comscore|krux|bluekai|exelate|adform|adroll|rubicon|vungle|inmobi|flurry|mixpanel|heap|amplitude|optimizely|bizible|pardot|hubspot|marketo|eloqua|salesforce|media(math|net)|criteo|appnexus|turn|adbrite|admob|adsonar|adscale|zergnet|revcontent|mgid|nativeads|contentad|displayads|bannerflow|adblade|adcolony|chartbeat|newrelic|pingdom|gauges|kissmetrics|webtrends|tradedesk|bidder|auction|rtb|programmatic|splash|interstitial|overlay)\./i;

// Regular Expression for Ad-Related URL Patterns
var adUrlRegex = /(?:\/(?:adcontent|img\/adv|web\-ad|iframead|contentad|ad\/image|video\-ad|stats\/event|xtclicks|adscript|bannerad|googlead|adhandler|adimages|embed\-log|adconfig|tracking\/track|tracker\/track|adrequest|nativead|adman|advertisement|adframe|adcontrol|adoverlay|adserver|adsense|google\-ads|ad\-banner|banner\-ad|campaign\/advertiser|adplacement|adblockdetect|advertising|admanagement|adprovider|adrotation|adtop|adbottom|adleft|adright|admiddle|adlarge|adsmall|admicro|adunit|adcall|adlog|adcount|adserve|adsrv|adsys|adtrack|adview|adwidget|adzone|banner\/adv|google_tag|image\/ads|sidebar\-ads|footer\-ads|top\-ads|bottom\-ads|new\-ads|search\-ads|lazy\-ads|responsive\-ads|dynamic\/ads|external\/ads|mobile\-ads|house\-ads|blog\/ads|online\/ads|pc\/ads|left\-ads|right\-ads|ads\/square|ads\/text|ads\/html|ads\/js|ads\.php|ad\.js|ad\.css|\?affiliate=|\?advertiser=|\&adspace=|\&adserver=|\&adgroupid=|\&adpageurl=|\.adserve|\.ads\d|\.adspace|\.adsense|\.adserver|\.google\-ads|\.banner\-ad|\.ad\-banner|\.adplacement|\.advertising|\.admanagement|\.adprovider|\.adrotation|\.adtop|\.adbottom|\.adleft|\.adright|\.admiddle|\.adlarge|\.adsmall|\.admicro|\.adunit|\.adcall|\.adlog|\.adcount|\.adserve|\.adsrv|\.adsys|\.adtrack|\.adview|\.adwidget|\.adzone))/i;

// Regular Expression for Common Ad Subdomains
var adSubdomainRegex = /^(?:adcreative(s)?|imageserv|media(mgr)?|stats|switch|track(2|er)?|view|ad(s)?\d{0,3}|banner(s)?\d{0,3}|click(s)?\d{0,3}|count(er)?\d{0,3}|servedby\d{0,3}|toolbar\d{0,3}|pageads\d{0,3}|pops\d{0,3}|promos\d{0,3})\./i;

// Regular Expression for Web Bugs and Flash Ads
var adWebBugRegex = /(?:\/(?:1|blank|b|clear|pixel|transp|spacer)\.gif|\.swf)$/i;

// Blacklist: Explicitly blocked domains
var blacklist = [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adserver.com",
    "fastclick.com",
    "adnxs.com",
    "adtech.com",
    "advertising.com",
    "atdmt.com",
    "quantserve.com",
    "omniture.com",
    "comscore.com",
    "scorecardresearch.com",
    "chartbeat.com",
    "newrelic.com",
    "pingdom.com",
    "kissmetrics.com",
    "webtrends.com",
    "tradedesk.com",
    "criteo.com",
    "appnexus.com",
    "turn.com",
    "adbrite.com",
    "admob.com",
    "adsonar.com",
    "adscale.com",
    "zergnet.com",
    "revcontent.com",
    "mgid.com",
    "nativeads.com",
    "contentad.com",
    "displayads.com",
    "bannerflow.com",
    "adblade.com",
    "adcolony.com",
    "outbrain.com",
    "taboola.com",
    "quantcast.com",
    "krux.com",
    "bluekai.com",
    "exelate.com",
    "adform.com",
    "adroll.com",
    "rubiconproject.com",
    "vungle.com",
    "inmobi.com",
    "flurry.com",
    "mixpanel.com",
    "heap.io",
    "amplitude.com",
    "optimizely.com",
    "bizible.com",
    "pardot.com",
    "hubspot.com",
    "marketo.com",
    "eloqua.com",
    "salesforce.com",
    "media.net",
    "247media.com",
    "247realmedia.com",
    "2o7.net",
    "3721.com",
    "180solutions.com",
    "zedo.com",
    "zango.com",
    "virtumundo.com",
    "valueclick.com",
    "vonna.com",
    "webtrendslive.com",
    "weatherbug.com",
    "webhancer.com",
    "websponsors.com",
    "xiti.com",
    "xxxcounter.com",
    "myway.com",
    "mysearch.com",
    "mygeek.com",
    "mycomputer.com",
    "moreover.com",
    "mspaceads.com",
    "mediaplex.com",
    "madserver.net",
    "netgravity.com",
    "networldmedia.net",
    "overture.com",
    "oingo.com",
    "ourtoolbar.com",
    "offeroptimizer.com",
    "offshoreclicks.com",
    "opistat.com",
    "opentracker.net",
    "paypopup.com",
    "paycounter.com",
    "popupsponsor.com",
    "popupmoney.com",
    "p2l.info",
    "pharmacyfarm.info",
    "popupad.net",
    "pharmacyheaven.biz",
    "qsrch.com",
    "quigo.com",
    "qckads.com",
    "realmedia.com",
    "radiate.com",
    "redsheriff.com",
    "realtracker.com",
    "readnotify.com",
    "searchx.cc",
    "sextracker.com",
    "sabela.com",
    "spywarequake.com",
    "spywarestrike.com",
    "searchmiracle.com",
    "starware.com",
    "starwave.com",
    "swirve.com",
    "spyaxe.com",
    "spylog.com",
    "search.com",
    "servik.com",
    "searchfuel.com",
    "search.com.com",
    "spyfalcon.com",
    "sitemeter.com",
    "statcounter.com",
    "sitestats.com",
    "superstats.com",
    "sitestat.com",
    "sexlist.com",
    "scaricare.ws",
    "speedera.net",
    "targetpoint.com",
    "tempx.cc",
    "topx.cc",
    "trafficsyndicate.com",
    "teknosurf.com",
    "timesink.com",
    "tradedoubler.com",
    "thecounter.com",
    "targetwords.com",
    "telecharger-en-francais.com",
    "trafficserverstats.com",
    "targetnet.com",
    "telecharger-soft.com",
    "thruport.com",
    "tdmy.com",
    "telecharger.ws",
    "tribalfusion.com",
    "utopiad.com",
    "web3000.com",
    "gratisware.com",
    "grandstreetinteractive.com",
    "gambling.com",
    "goclick.com",
    "gohip.com",
    "gator.com",
    "gmx.net",
    "hit-parade.com",
    "humanclick.com",
    "hotbar.com",
    "hpwis.com",
    "hitbox.com",
    "hpg.ig.com.br",
    "hpg.com.br",
    "hyperbanner.net",
    "hypermart.net",
    "intellitxt.com",
    "ivwbox.de",
    "imaginemedia.com",
    "imrworldwide.com",
    "inetinteractive.com",
    "insightexpressai.com",
    "inspectorclick.com",
    "internetfuel.com",
    "iwon.com",
    "imgis.com",
    "insightexpress.com",
    "intellicontact.com",
    "insightfirst.com",
    "just404.com",
    "kadserver.com",
    "linklist.cc",
    "linkexchange.com",
    "links4trade.com",
    "linkshare.com",
    "linksponsor.com",
    "link4ads.com",
    "livestat.com",
    "liveadvert.com",
    "linksynergy.com",
    "linksummary.com",
    "liteweb.net",
    "mtree.com",
    "malwarewipe.com",
    "marketscore.com",
    "maxserving.com",
    "mywebsearch.com",
    "nextlevel.com",
    "netster.com",
    "nastydollars.com",
    "pentoninteractive.com",
    "porntrack.com",
    "precisionclick.com",
    "freebannertrade.com",
    "focalink.com",
    "friendfinder.com",
    "flyswat.com",
    "firehunt.com",
    "flycast.com",
    "focalex.com",
    "flyingcroc.net",
    "falkag.net",
    "errorsafe.com",
    "esomniture.com",
    "eimg.com",
    "ezcybersearch.com",
    "erasercash.com",
    "extreme-dm.com",
    "ezgreen.com",
    "enliven.com",
    "eacceleration.com",
    "einets.com",
    "esthost.com",
    "euroclick.net",
    "clicktorrent.info",
    "count.cc",
    "click2net.com",
    "casalemedia.com",
    "channelintelligence.com",
    "clicktrade.com",
    "clickhype.com",
    "cpxinteractive.com",
    "coolwebsearch.com",
    "clrsch.com",
    "cj.com",
    "chickclick.com",
    "comclick.com",
    "cqcounter.com",
    "clicksor.com",
    "climaxbucks.com",
    "cometsystems.com",
    "clickfinders.com",
    "clickagents.com",
    "conducent.com",
    "clickability.com",
    "cjt1.net",
    "clickbank.net",
    "doubleclick.com",
    "direct-revenue.com",
    "decideinteractive.com",
    "drsnsrch.com",
    "directtrack.com",
    "dotbiz4all.com",
    "drmwrap.com",
    "domainsponsor.com",
    "download-software.us",
    "descarregar.net",
    "bannercommunity.de",
    "bpath.com",
    "bonzi.com",
    "bluestreak.com",
    "bannermall.com",
    "blogads.com",
    "bestoffersnetworks.com",
    "bannerhosts.com",
    "bfast.com",
    "bnex.com",
    "beesearch.info",
    "baixar.ws",
    "bannerconnect.net",
    "bargain-buddy.net",
    "atdmt.com",
    "adultadworld.com",
    "adlink.com",
    "ads360.com",
    "affiliatetargetad.com",
    "advertwizard.com",
    "adknowledge.com",
    "adsoftware.com",
    "andlotsmore.com",
    "aureate.com",
    "adbrite.com",
    "aavalue.com",
    "advertserve.com",
    "adsrve.com",
    "admaximize.com",
    "adultcash.com",
    "accessplugin.com",
    "adsonar.com",
    "adroar.com",
    "addr.com",
    "adrevolver.com",
    "akamaitechnologies.com",
    "amazingcounters.com",
    "allowednet.com",
    "ad-flow.com",
    "adflow.com",
    "alfaspace.net",
    "advance.net",
    "akamaitech.net",
    "akamai.net",
    "adbureau.net"
];

// Main Proxy Auto-Configuration Function
function FindProxyForURL(url, host) {
    // Convert inputs to lowercase for case-insensitive matching
    host = host.toLowerCase();
    url = url.toLowerCase();

    // Debugging output (if enabled)
    if (debug) {
        alert("Checking...\nURL: " + url + "\nHost: " + host);
    }

    // Toggle ad-blocking on/off via special URLs
    if (host === "antiad.on") {
        isEnabled = 1;
        if (debug) alert("Ad-blocking enabled");
        return blackhole;
    } else if (host === "antiad.off") {
        isEnabled = 0;
        if (debug) alert("Ad-blocking disabled");
        return blackhole;
    }

    // If ad-blocking is disabled, pass all traffic
    if (!isEnabled) {
        return normal;
    }

    // Local network bypass (e.g., LAN, loopback)
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "127.*") ||
        dnsDomainIs(host, ".local")) {
        return normal;
    }

    // Whitelist check: Allow explicitly whitelisted domains
    for (var i = 0; i < whitelist.length; i++) {
        if (shExpMatch(host, whitelist[i])) {
            if (debug) alert("Whitelisted: " + host);
            return normal;
        }
    }

    // Ad-blocking logic
    if (
        // Match ad-related domains
        adDomainRegex.test(host) ||
        // Match ad-related URL patterns
        adUrlRegex.test(url) ||
        // Match common ad subdomains
        adSubdomainRegex.test(host) ||
        // Match web bugs and Flash ads
        adWebBugRegex.test(url) ||
        // Match explicitly blacklisted domains
        blacklist.indexOf(host) !== -1
    ) {
        if (debug) alert("Blocked...\nURL: " + url + "\nHost: " + host);
        return blackhole;
    }

    // Default: Pass through all non-matching traffic
    if (debug) alert("Not Blocked...\nURL: " + url + "\nHost: " + host);
    return normal;
}

// Initial load notification (if debugging is enabled)
if (debug) {
    alert("Ad-blocking PAC file loaded, isEnabled = " + isEnabled);
}
