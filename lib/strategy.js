// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var crypto = require('crypto')

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://account.xiaomi.com/oauth2/authorize'
  options.tokenURL = options.tokenURL || 'https://account.xiaomi.com/oauth2/token'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-xiaomi'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'xiaomi'
  this._userProfileURL = options.userProfileURL || 'https://open.account.xiaomi.com/user/profile'
  this._host = options.host || 'open.account.xiaomi.com'
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['client_id'] = this._clientId
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['client_id'] = this._clientId
    params['client_secret'] = this._clientSecret
    params['grant_type'] = 'authorization_code'
    // var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'authorization_code'
    params['code'] = code

    var post_data = querystring.stringify(params)

    this._request('GET', this._getAccessTokenUrl() + '?' + post_data, null, null, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results
        try {
          results = JSON.parse(data.slice(11))
        } catch (e) {
          results = querystring.parse(data.slice(11))
        }
        var access_token = results['access_token']
        var refresh_token = results['refresh_token']
        delete results['refresh_token']
        callback(null, access_token, refresh_token, results) // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (params, done) {
  if (!params.access_token || !params.mac_key) {
    return done(new Error('access_token and mac_key is required for userProfile api'))
  }
  var macKey = params.mac_key
  var nonce = generateNonce()
  var qs = querystring.stringify({
    clientId: this._oauth2._clientId,
    token: params.access_token
  })
  var macStr = generateMac(macKey, nonce, 'GET', this._host, '/user/profile', qs)
  var headers = {
    'Authorization': 'MAC access_token="' + params.access_token + '",nonce="' + nonce + '",mac="' + macStr + '"'
  }
  this._oauth2._request('GET', this._userProfileURL + '?' + qs, headers, null, null, function (err, body, res) {
    var json
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data)
        } catch (_) {}
      }

      if (json && json.message) {
        return done(new Error(json.message))
      }
      return done(new Error('Failed to fetch user profile'))
    }

    try {
      json = JSON.parse(body)
      return done(null, json)
    } catch (ex) {
      return done(new Error('Failed to parse user profile'))
    }
  })
}

function generateNonce () {
  var random = Math.random().toString().slice(2)
  var timestamp = Math.floor(Date.now() / 1000 / 60).toString()
  return random + ':' + timestamp
}

// used for xiaomi auth header
function generateMac (macKey, nonce, method, host, uri, qs) {
  var macStr = [nonce, method.toUpperCase(), host, uri, qs, ''].join('\n')
  return querystring.escape(crypto.createHmac('sha1', macKey).update(macStr).digest('base64'))
}

// Expose constructor.
module.exports = Strategy
