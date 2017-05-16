var cache = false;
var store = require('/modules/store.js');
var engine = caramel.engine('handlebars', (function () {
    return {
        partials: function (Handlebars) {
            var theme = caramel.theme();
            var partials = function (file) {
                (function register(prefix, file) {
                    var i, length, name, files;
                    if (file.isDirectory()) {
                        files = file.listFiles();
                        length = files.length;
                        for (i = 0; i < length; i++) {
                            file = files[i];
                            register(prefix ? prefix + '.' + file.getName() : file.getName(), file);
                        }
                    } else {
                        name = file.getName();
                        if (name.substring(name.length - 4) !== '.hbs') {
                            return;
                        }
                        file.open('r');
                        Handlebars.registerPartial(prefix.substring(0, prefix.length - 4), file.readAll());
                        file.close();
                    }
                })('', file);
            };
            //TODO : we don't need to register all partials in the themes dir.
            //Rather register only not overridden partials
            var PARTIALS = 'partials';
            //register default theme(store/themes) partials
            partials(new File(theme.__proto__.resolve.call(theme, PARTIALS)));

            var tenantDomain = resolveTenant();
            cacheCustomThemeInfo(tenantDomain);
            //register partials from custom default theme
            if(isCustomThemeExist(tenantDomain,'default')) {
                var path =  getCustomDefaultThemePath(tenantDomain) + "/" + PARTIALS;
                var dir = new File(path);
                if (dir.isExists()) {
                    partials(dir);
                }
            }

            var asset = getCurrentAsset();

            if(asset) {
                var themeName = caramel.configs().themer();
                //register partials from asset  extension theme
                var path = getAssetThemePath(asset,themeName)+ "/" + PARTIALS;
                var dir = new File(path);
                if (dir.isExists()) {
                    partials(dir);
                }

                //register partial from custom theme of asset extension theme
                if(isCustomThemeExist(tenantDomain, asset)) {
                    var path = getCustomAssetThemePath(tenantDomain,asset)+ "/" + PARTIALS;
                    var dir = new File(path);
                    if (dir.isExists()) {
                        partials(dir);
                    }
                }
            }



            Handlebars.registerHelper('pagesloop', function(n, block) {
                var accum = '';
                for(var i = 1; i <= n; ++i)
                    accum += block.fn(i);
                return accum;
            });

            Handlebars.registerHelper('assetRating', function(rating, options) {
                var optionsHash = options.hash;
                var min = optionsHash['min'] || 0;
                var max = optionsHash['max'] || 5;
                var ratedHtml = optionsHash['ratedHtml'] || '<i class="fw fw-star one"></i>';
                var unratedHtml = optionsHash['unratedHtml'] || '<i class="fw fw-star zero"></i>';
                rating = parseInt(rating);
                var htmlBuffer = [];
                var i = min;
                for (; i < max; i++) {
                    if (i < rating) {
                        htmlBuffer.push(ratedHtml);
                    } else {
                        htmlBuffer.push(unratedHtml);
                    }
                }
                return new Handlebars.SafeString(htmlBuffer.join(" "));
            });


            Handlebars.registerHelper('iconImage', function(imageName) {
                if(imageName == 'android'){
                    return 'fw-android fw-background-green';
                }else if(imageName == 'ios'){
                    return 'fw-apple fw-background-black';
                }else if(imageName == 'webapp'){
                    return 'fw-web-app fw-background-blue';
                }
            });

            Handlebars.registerHelper('iconImageType', function(imageName) {
                if(imageName == 'enterprise'){
                    return 'fw-enterprise-app fw-background-gray';
                }else if(imageName == 'public'){
                    return 'fw-public-app fw-background-gray';
                }else if(imageName == 'webapp'){
                    return 'fw-webclip fw-background-gray';
                }
            });

            /**
             * Registers  'tenantedUrl' handler for resolving tenanted urls '{context}/t/{domain}/
             */
            Handlebars.registerHelper('tenantedUrl', function (path) {

                var log = new Log();
                var uri = request.getRequestURI();//current page path
                var context, domain, output;
                var matcher = new URIMatcher(uri);
                var storageMatcher = new URIMatcher(path);
                var mobileApiMatcher = new URIMatcher(path);
                var caramel = require('caramel');
                var context = caramel.configs().context;
                var pattern = context + '/storage/{+any}';
                var customDomainHeader = request.getHeader("wso2-cloud-custom-domain");
                //Resolving tenanted storage URI for webapps
                if (storageMatcher.match(pattern)) {
                    path = "/storage/" + storageMatcher.elements().any;
                }
                //TODO: This url pattern has been hard coded due to pattern mismatch in between mobile and webapp image
                // urls

                //Resolving mobile app image urls
                if (mobileApiMatcher.match('/publisher/api/{+any}')) {
                    return path;
                }

                //If custom urls has been set, we just need to return '/'.
                if (customDomainHeader) {
                    return path;
                }
                if (matcher.match('/{context}/t/{domain}/') || matcher.match('/{context}/t/{domain}/{+any}')) {
                    domain = matcher.elements().domain;
                    output = context + '/t/' + domain;
                    return output + path;
                } else {
                    if (path.indexOf('http://') === 0 || path.indexOf('https://') === 0) {
                        return path;
                    }
                    return caramel.url(path);
                }

            });

            Handlebars.registerHelper('isTenanted', function (path) {
                var uri = request.getRequestURI();//current page path
                var matcher = new URIMatcher(uri);

                if (matcher.match('/{context}/t/{domain}/') || matcher.match('/{context}/t/{domain}/{+any}')) {
                    return true;
                } else {
                    return false;
                }

            });

            //return the current tenant domain based on tenanted url
            Handlebars.registerHelper('currentTenant', function (path) {
                var uri = request.getRequestURI();//current page path
                var matcher = new URIMatcher(uri);

                if (matcher.match('/{context}/t/{domain}/') || matcher.match('/{context}/t/{domain}/{+any}')) {
                    return matcher.elements().domain;
                } else {
                    return 'carbon.super';
                }

            });

            //Resolve the resource url from correct theme dir
            Handlebars.registerHelper('customThemeUrl', function (path) {
                var theme = caramel.theme();
                var url = theme.url;
                return url.call(theme, path);
            });

            Handlebars.registerHelper('socialURL', function (path) {
                var socialAppContext = caramel.configs().socialAppContext;
                var reverseProxyEnabled = caramel.configs().reverseProxyEnabled;
                var reverseProxyHost = caramel.configs().reverseProxyHost;
                var ip = process.getProperty('server.host');
                var https = process.getProperty('https.port');
                var http = process.getProperty('http.port');
                var url = ip + ":" + https + socialAppContext;
                if (reverseProxyEnabled) {
                    url = reverseProxyHost + socialAppContext;
                } else {
                    var isSecure = request.isSecure();
                    if (isSecure) {
                        url = "https://" + ip + ":" + https + socialAppContext
                    } else {
                        url = "http://" + ip + ":" + http + socialAppContext
                    }
                }
                return url;

            });

            Handlebars.registerHelper('compare', function (lvalue, rvalue, options) {

                if (arguments.length < 3)
                    throw new Error("Handlerbars Helper 'compare' needs 2 parameters");

                operator = options.hash.operator || "==";

                var operators = {
                    '==': function (l, r) {
                        return l == r;
                    },
                    '===': function (l, r) {
                        return l === r;
                    },
                    '!=': function (l, r) {
                        return l != r;
                    },
                    '<': function (l, r) {
                        return l < r;
                    },
                    '>': function (l, r) {
                        return l > r;
                    },
                    '<=': function (l, r) {
                        return l <= r;
                    },
                    '>=': function (l, r) {
                        return l >= r;
                    },
                    'typeof': function (l, r) {
                        return typeof l == r;
                    }
                }

                if (!operators[operator])
                    throw new Error("Handlerbars Helper 'compare' doesn't know the operator " + operator);

                var result = operators[operator](lvalue, rvalue);

                if (result) {
                    return options.fn(this);
                } else {
                    return options.inverse(this);
                }

            });


            Handlebars.registerHelper("math", function(lvalue, operator, rvalue, options) {
                lvalue = parseFloat(lvalue);
                rvalue = parseFloat(rvalue);

                return {
                    "+": lvalue + rvalue,
                    "-": lvalue - rvalue,
                    "*": lvalue * rvalue,
                    "/": lvalue / rvalue,
                    "%": lvalue % rvalue
                }[operator];
            });


            Handlebars.registerHelper('dyn', function (options) {
                var asset = options.hash.asset,
                    resolve = function (path) {
                        var p,
                            store = require('/modules/store.js');
                        if (asset) {
                            p = store.ASSETS_EXT_PATH + asset + '/themes/' + theme.name + '/' + path;
                            if (new File(p).isExists()) {
                                return p;
                            }
                        }
                        return theme.__proto__.resolve.call(theme, path);
                    };
                partials(new File(resolve('partials')));
                return options.fn(this);
            });

            Handlebars.registerHelper('ifCond', function (v1, operator, v2, options) {

                switch (operator) {
                    case '==':
                        return (v1 == v2) ? options.fn(this) : options.inverse(this);
                    case '!=':
                        return (v1 != v2) ? options.fn(this) : options.inverse(this);
                    case '===':
                        return (v1 === v2) ? options.fn(this) : options.inverse(this);
                    case '<':
                        return (v1 < v2) ? options.fn(this) : options.inverse(this);
                    case '<=':
                        return (v1 <= v2) ? options.fn(this) : options.inverse(this);
                    case '>':
                        return (v1 > v2) ? options.fn(this) : options.inverse(this);
                    case '>=':
                        return (v1 >= v2) ? options.fn(this) : options.inverse(this);
                    default:
                        return options.inverse(this);
                }
            });
        },
        render: function (data, meta) {
            if (request.getParameter('debug') == '1') {
                response.addHeader("Content-Type", "application/json");
                print(stringify(data));
            } else {
                this.__proto__.render.call(this, data, meta);
            }
        },
        globals: function (data, meta) {
            var store = require('/modules/store.js'),
                user = require('store').server.current(meta.session);
            return 'var store = ' + stringify({
                user: user ? user.username : null
            });
        }
    };
}()));

var resolve = function (path) {
    var p;
    path = (path.charAt(0) !== '/' ? '/' : '') + path;
    var asset = getCurrentAsset();
    var tenantDomain = resolveTenant();

    /*************resolve path in custom  theme*****************/

    if(isCustomThemeExist(tenantDomain,null)) {
        //if extension level theme is overridden
        if(asset && isCustomThemeExist(tenantDomain,asset)) {
            p = getCustomAssetThemePath(tenantDomain,asset) +  path;
            if (new File(p).isExists()) {
                return p;
            }
        }
        //default theme is overridden
        if(isCustomThemeExist(tenantDomain,'default')) {
            p = getCustomDefaultThemePath(tenantDomain) +  path;
            if (new File(p).isExists()) {
                return p;
            }
        }
    }

    /*************resolve path from default theme *************/
    if (asset) {
        //if default theme is overridden in extension level
        p = getAssetThemePath(asset,this.name) +  path;
        if (new File(p).isExists()) {
            return p;
        }
    }
    return this.__proto__.resolve.call(this, path);
};

var resolveTenant = function () {
    var uriMatcher = new URIMatcher(request.getRequestURI());
    var tenantPages= '/{context}/t/{tenantDomain}/{+suffix}';
    var tenantHomePage = '/{context}/t/{tenantDomain}/';
    var tenantDomain = 'carbon.super';
    //Provide a pattern to be matched against the URL
    if(uriMatcher.match(tenantHomePage) || uriMatcher.match(tenantPages)) {
        //If pattern matches, elements can be accessed from their keys
        var elements = uriMatcher.elements();
        tenantDomain = elements.tenantDomain;
    }
    return tenantDomain;
};

var cacheCustomThemeInfo = function(tenantDomain) {
    //check already cached
    var key = 'theme_' + tenantDomain;
    var info = session.get(key);
    if(info) {
        return;
    }

    var customThemes = [];
    //check custom theme exists
    var customThemePath = "/themes/" + tenantDomain;
    if(new File(customThemePath).isExists()) {
        //check default custom theme exists
        var defaultTheme = customThemePath + "/themes";
        if(new File(defaultTheme).isExists()) {
            customThemes.push('default');
        }
        //check asset level custom theme exists
        var extPath = customThemePath + "/extensions/assets/";
        var assets = require('/config/store-tenant.json').assets;
        var count = assets.length;
        for(var i =0 ; i < count ; i++) {
            var path = extPath + assets[i];
            if(new File(path).isExists()) {
                customThemes.push(assets[i])
            }
        }
    }
    session.put(key,customThemes);
};

var isCustomThemeExist = function (tenantDomain,type){
    var key = "theme_" + tenantDomain;
    var customThemes = session.get(key);
    var isExists = false;

    if(!customThemes && customThemes.length == 0) {
        return isExists;
    }

    if(type) {
        if(customThemes.indexOf(type) >= 0) {
            isExists= true;
        }
    } else if(customThemes.length > 0) {
        isExists = true;
    }

    return isExists;
};

var getCurrentAsset = function () {
    return store.currentAsset();
};

var getThemeExtPath = function(tenantDomain) {
    return "/themes/" + tenantDomain;
};

var getCustomDefaultThemePath = function (tenantDomain) {
    return getThemeExtPath(tenantDomain) + "/themes/custom";
};

var getCustomAssetThemePath = function(tenantDomain,asset) {
    return getThemeExtPath(tenantDomain) + "/extensions/assets/" + asset + "/themes/custom";
};

var getAssetThemePath = function(asset,themeName) {
    return store.ASSETS_EXT_PATH + asset + '/themes/' + themeName;
};