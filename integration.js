'use strict';

const request = require('postman-request');
const _ = require('lodash');
const fp = require('lodash/fp');
const {
  flow,
  get,
  compact,
  isString,
  isPlainObject,
  some,
  values,
  groupBy,
  toPairs,
  flatMap,
  uniq,
  reduce,
  entries,
  replace,
  startCase,
  includes,
  size,
  uniqBy,
  sortBy,
  keys,
  isArray,
  curry,
  find,
  assign,
  mapValues,
  forEach,
  isEmpty,
  omitBy,
  isUndefined,
  filter
} = fp;

const showdown = require('showdown');
showdown.setOption('tables', true);
const showdownConverter = new showdown.Converter();
const convertMarkdownToHtml = (text) => showdownConverter.makeHtml(text);

const map = require('lodash/fp/map').convert({ cap: false });
const config = require('./config/config');
const async = require('async');
const PendingLookupCache = require('./lib/pending-lookup-cache');
const fs = require('fs');
let schedule = require('node-schedule');

const { knownThreatActors } = require('./lib/constants');

let Logger = {
  trace: (args, msg) => {
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};
let pendingLookupCache = new PendingLookupCache(Logger);
let domainUrlBlocklistRegex = null;
let ipBlocklistRegex = null;
let compiledThresholdRules = [];
let previousBaselineInvestigationThreshold = null;
let doLookupLogging;
let lookupHashSet;
let lookupIpSet;
let lookupDomainSet;
let lookupUrlSet;
let lookupCveSet;
let job;

let requestWithDefaults = request.defaults({ json: true });

const debugLookupStats = {
  hourCount: 0,
  dayCount: 0,
  hashCount: 0,
  ipCount: 0,
  ipLookups: 0,
  domainCount: 0,
  domainLookups: 0,
  urlCount: 0,
  urlLookups: 0,
  hashLookups: 0
};

const threatActorNames = knownThreatActors;
const throttleCache = new Map();
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const LOOKUP_URI_BY_TYPE = {
  ip: 'https://www.virustotal.com/api/v3/ip_addresses',
  domain: 'https://www.virustotal.com/api/v3/domains',
  hash: 'https://www.virustotal.com/api/v3/files',
  url: 'https://www.virustotal.com/api/v3/urls'
};

const TYPES_BY_SHOW_NO_DETECTIONS = {
  ip: 'showIpsWithNoDetections',
  domain: 'showDomainsWithNoDetections',
  hash: 'showHashesWithNoDetections',
  url: 'showUrlsWithNoDetections'
};

const GTI_LOOKUP_LIMIT = 5;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
  // if the threshold rules are disabled then we want an empty rule set (empty array)
  if (options.baselineInvestigationThresholdEnabled === false) {
    compiledThresholdRules = [];
    previousBaselineInvestigationThreshold = null;
  }

  // We only want to compile our threshold rules if the option has changed
  // The option is intended to be admin-only
  if (
    options.baselineInvestigationThresholdEnabled &&
    (options.baselineInvestigationThreshold !== previousBaselineInvestigationThreshold ||
      previousBaselineInvestigationThreshold === null)
  ) {
    compiledThresholdRules = parseBaselineInvestigationThreshold(
      options.baselineInvestigationThreshold
    );
    previousBaselineInvestigationThreshold = options.baselineInvestigationThreshold;
  }

  if (throttleCache.has(options.apiKey)) {
    // the throttleCache stores whether or not we've shown the throttle warning message for this throttle duration
    // We only want to show the message once per throttleDuration (defaults to 1 minute).
    if (options.warnOnThrottle && !throttleCache.get(options.apiKey)) {
      throttleCache.set(options.apiKey, true);
      return cb(`Throttling lookups for ${options.lookupThrottleDuration} minute`, []);
    } else {
      return cb(null, []);
    }
  }

  let ipv4Entities = new Array();
  let domainEntities = new Array();
  let urlEntities = new Array();
  let cveEntities = new Array();
  let entityLookup = {};
  let hashGroups = [];
  let hashGroup = [];
  let nonCveOrThreatActorEntities = entities; // [];
  let threatActorsEntities = [];

  Logger.trace(entities);
  const MAX_HASHES_PER_GROUP = options.maxHashesPerGroup;

  entities.forEach(function (entity) {
    if (pendingLookupCache.isRunning(entity.value))
      return pendingLookupCache.addPendingLookup(entity.value, cb);

    if (_isEntityBlocked(entity, options)) {
      return;
    }

    // if (entity.type === 'custom') {
    //   if (threatActorNames.includes(entity.value)) {
    //     threatActorsEntities.push(entity);
    //   }
    // } else if (entity.type !== 'cve') {
    //   nonCveOrThreatActorEntities.push(entity);
    // }

    if (entity.isMD5 || entity.isSHA1 || entity.isSHA256) {
      // VT can only look up 4 or 25 hashes at a time depending on the key type
      // so we need to split up hashes into groups of 4 or 25
      if (hashGroup.length >= MAX_HASHES_PER_GROUP) {
        hashGroups.push(hashGroup);
        hashGroup = [];
      }

      if (!entityLookup[entity.value.toLowerCase()]) {
        // entity isn't already added
        hashGroup.push(entity.value);
        entityLookup[entity.value.toLowerCase()] = entity;
        pendingLookupCache.addRunningLookup(entity.value);

        if (doLookupLogging) lookupHashSet.add(entity.value);
      }
    } else if (entity.isIPv4 && !entity.isPrivateIP && !IGNORED_IPS.has(entity.value)) {
      if (doLookupLogging) lookupIpSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      ipv4Entities.push(entity);
    } else if (entity.isDomain) {
      if (doLookupLogging) lookupDomainSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      domainEntities.push(entity);
    } else if (entity.isURL) {
      if (doLookupLogging) lookupUrlSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      urlEntities.push(entity);
    } else if (entity.types.includes('cve')) {
      if (doLookupLogging) lookupCveSet.add(entity.value);

      pendingLookupCache.addRunningLookup(entity.value);

      cveEntities.push(entity);
    }
  });

  // grab any "trailing" hashes
  if (hashGroup.length > 0) {
    hashGroups.push(hashGroup);
  }

  async.parallel(
    {
      ipLookups: function (callback) {
        if (ipv4Entities.length > 0) {
          async.concat(
            ipv4Entities,
            function (ipEntity, concatDone) {
              Logger.debug({ ip: ipEntity.value }, 'Looking up IP');
              _lookupEntityType('ip', ipEntity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      domainLookups: function (callback) {
        if (domainEntities.length > 0) {
          async.concat(
            domainEntities,
            function (domainEntity, concatDone) {
              Logger.debug({ domain: domainEntity.value }, 'Looking up Domain');
              _lookupEntityType('domain', domainEntity, options, concatDone);
            },
            function (err, results) {
              if (err) {
                Logger.error({ err, results }, 'Domain Search Failed');
                return callback(err);
              }

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      urlLookups: function (callback) {
        if (urlEntities.length > 0) {
          async.concat(
            urlEntities,
            function (urlEntity, concatDone) {
              Logger.debug({ url: urlEntity.value }, 'Looking up URL');
              _lookupUrl(urlEntity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      hashLookups: function (callback) {
        if (hashGroups.length > 0) {
          Logger.debug({ hashGroups: hashGroups }, 'Looking up HashGroups');
          async.map(
            hashGroups,
            function (hashGroup, mapDone) {
              _lookupHash(hashGroup, entityLookup, options, mapDone);
            },
            function (err, results) {
              if (err) return callback(err);

              Logger.trace({ hashLookupResults: results }, 'HashLookup Results');

              //results is an array of hashGroup results (i.e., an array of arrays)
              let unrolledResults = [];
              forEach((hashGroup) => {
                forEach((hashResult) => {
                  unrolledResults.push(hashResult);
                }, hashGroup);
              }, results);

              callback(null, unrolledResults);
            }
          );
        } else {
          callback(null, []);
        }
      },
      // cveLookups: function (callback) {
      //   if (cveEntities.length > 0) {
      //     async.concat(
      //       cveEntities,
      //       function (entity, concatDone) {
      //         Logger.debug({ cve: entity.value }, 'Looking up CVE');
      //         _lookupVulnerabilities(entity, options, concatDone);
      //       },
      //       function (err, results) {
      //         if (err) return callback(err);

      //         callback(null, results);
      //       }
      //     );
      //   } else {
      //     callback(null, []);
      //   }
      // },
      // threatActorLookups: function (callback) {
      //   if (threatActorsEntities.length > 0) {
      //     async.concat(
      //       threatActorsEntities,
      //       function (entity, concatDone) {
      //         Logger.debug(
      //           { threatActor: entity.value },
      //           'Looking up Threat Actors by Name'
      //         );
      //         _lookupThreatActors(entity, options, concatDone);
      //       },
      //       function (err, results) {
      //         if (err) return callback(err);

      //         callback(null, results);
      //       }
      //     );
      //   } else {
      //     callback(null, []);
      //   }
      // },
      threatLookups: function (callback) {
        if (nonCveOrThreatActorEntities.length > 0) {
          async.concat(
            nonCveOrThreatActorEntities,
            function (entity, concatDone) {
              Logger.debug({ entity: entity.value }, 'Looking up Threats');
              _lookupThreats(entity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      },
      reportLookups: function (callback) {
        if (nonCveOrThreatActorEntities.length > 0) {
          async.concat(
            nonCveOrThreatActorEntities,
            function (entity, concatDone) {
              Logger.debug({ entity: entity.value }, 'Looking up Threats');
              _lookupReports(entity, options, concatDone);
            },
            function (err, results) {
              if (err) return callback(err);

              callback(null, results);
            }
          );
        } else {
          callback(null, []);
        }
      }
    },
    function (err, lookupResults) {
      if (err) {
        pendingLookupCache.reset();
        return cb(err);
      }

      let combinedResults = new Array();

      [
        'hashLookups',
        'ipLookups',
        'domainLookups',
        'urlLookups'
        // 'cveLookups',
        // 'threatActorLookups'
      ].forEach((key) =>
        lookupResults[key].forEach(function (lookupResult) {
          if (lookupResult && lookupResult.data && lookupResult.data.details) {
            lookupResult.data.details.compiledBaselineInvestigationRules =
              compiledThresholdRules;
          }

          pendingLookupCache.removeRunningLookup(fp.get('entity.value', lookupResult));
          pendingLookupCache.executePendingLookups(lookupResult);

          combinedResults.push(lookupResult);
        })
      );

      const finalLookupResults = flow(
        mapValues((lookupResult) =>
          addThreatsAndReportsToLookupResult(lookupResult, lookupResults)
        ),
        values
      )(combinedResults);

      pendingLookupCache.logStats();

      cb(null, finalLookupResults);
    }
  );
}

const addThreatsAndReportsToLookupResult = (lookupResult, lookupResults) => {
  // Threats
  const { threats, threatsCount, threatsCursor } = flow(
    get('threatLookups'),
    find(({ entity }) => entity.value === lookupResult.entity.value),
    (threatData) => ({
      ...threatData,
      threats: get('threats', threatData),
      threatsCount: get('threatsCount', threatData),
      threatsCursor: get('threatsCursor', threatData)
    })
  )(lookupResults);

  if (threatsCount) {
    if (lookupResult.data === null) {
      lookupResult.data = {
        summary: [],
        details: {}
      };
    }
    lookupResult.data.summary = lookupResult.data.summary.concat(
      `Threats: ${threatsCount}`
    );
    lookupResult.data.details.threats = threats;
    lookupResult.data.details.threatsCount = threatsCount;
    lookupResult.data.details.threatsCursor = threatsCursor;
  }

  // Reports
  const { reports, reportsCount, reportsCursor } = flow(
    get('reportLookups'),
    find(({ entity }) => entity.value === lookupResult.entity.value),
    (reportData) => ({
      ...reportData,
      reports: get('reports', reportData),
      reportsCount: get('reportsCount', reportData),
      reportsCursor: get('reportsCursor', reportData)
    })
  )(lookupResults);

  if (reportsCount) {
    if (lookupResult.data === null) {
      lookupResult.data = {
        summary: [],
        details: {}
      };
    }
    lookupResult.data.summary = lookupResult.data.summary.concat(
      `Reports: ${reportsCount}`
    );
    lookupResult.data.details.reports = reports;
    lookupResult.data.details.reportsCount = reportsCount;
    lookupResult.data.details.reportsCursor = reportsCursor;
  }

  lookupResult.data.details.associationLink = `https://www.virustotal.com/gui/${getUiUrlByEntityType(
    lookupResult.entity
  )}`;

  if (
    get('data.summary', lookupResult) &&
    lookupResult.data.summary.includes('has not seen or scanned') &&
    lookupResult.data.summary.length > 1
  ) {
    lookupResult.data.summary = lookupResult.data.summary.filter(
      (summary) => !summary.includes('has not seen or scanned')
    );
  }

  return lookupResult;
};

function _isEntityBlocked(entity, options) {
  const blocklist = options.blocklist;
  const currentIpBlocklistRegex = options.ipBlocklistRegex;
  const currentDomainUrlBlocklistRegex = options.domainUrlBlocklistRegex;

  // initialize regex if needed
  if (ipBlocklistRegex === null && currentIpBlocklistRegex.length > 0) {
    Logger.debug('Initializing ip blocklist regex');
    ipBlocklistRegex = new RegExp(currentIpBlocklistRegex);
  }

  if (domainUrlBlocklistRegex === null && currentDomainUrlBlocklistRegex.length > 0) {
    Logger.debug('Initializing domain/url blocklist regex');
    domainUrlBlocklistRegex = new RegExp(currentDomainUrlBlocklistRegex);
  }

  if (currentIpBlocklistRegex.length === 0) {
    ipBlocklistRegex = null;
  }

  if (currentDomainUrlBlocklistRegex.length === 0) {
    domainUrlBlocklistRegex = null;
  }

  if (
    ipBlocklistRegex !== null &&
    ipBlocklistRegex.toString() !== `/${currentIpBlocklistRegex}/`
  ) {
    Logger.debug('Updating ipBlocklistRegex');
    ipBlocklistRegex = new RegExp(currentIpBlocklistRegex);
  }

  if (
    domainUrlBlocklistRegex !== null &&
    domainUrlBlocklistRegex.toString() !== `/${currentDomainUrlBlocklistRegex}/`
  ) {
    Logger.debug('Updating domainUrlBlocklistRegex');
    domainUrlBlocklistRegex = new RegExp(currentDomainUrlBlocklistRegex);
  }

  Logger.trace({ blocklist }, 'Blocklist value');

  if (_.includes(blocklist, entity.value.toLowerCase())) {
    Logger.debug({ entity: entity.value }, 'Blocked Entity');
    return true;
  }

  if (entity.isIP && !entity.isPrivateIP) {
    if (ipBlocklistRegex !== null) {
      if (ipBlocklistRegex.test(entity.value)) {
        Logger.debug({ ip: entity.value }, 'IP lookup blocked due to blocklist regex');
        return true;
      }
    }
  }

  if (entity.isDomain) {
    if (domainUrlBlocklistRegex !== null) {
      if (domainUrlBlocklistRegex.test(entity.value)) {
        Logger.debug(
          { domain: entity.value },
          'Domain lookup blocked due to blocklist regex'
        );
        return true;
      }
    }
  }

  if (entity.isURL) {
    if (domainUrlBlocklistRegex !== null) {
      const urlObj = new URL(entity.value);
      const hostname = urlObj.hostname;
      Logger.debug(hostname, 'Hostname of url to block');
      if (domainUrlBlocklistRegex.test(hostname)) {
        Logger.debug({ url: entity.value }, 'URL lookup blocked due to blocklist regex');
        return true;
      }
    }
  }

  return false;
}

function _removeFromThrottleCache(apiKey) {
  return function () {
    throttleCache.delete(apiKey);
  };
}

function _handleRequestError(err, response, body, options, cb) {
  if (err) {
    cb(
      _createJsonErrorPayload(
        'Unable to connect to GTI server',
        null,
        '500',
        '2A',
        'GTI HTTP Request Failed',
        {
          err: err
        }
      )
    );
    return;
  }

  if (response.statusCode === 429) {
    // This means the user has reached their request limit for the API key.  In this case,
    // we don't treat it as an error and just return no results.  In the future, integrations
    // might allow non-error messages to be passed back to the user such as (VT query limit reached)
    if (!throttleCache.has(options.apiKey)) {
      setTimeout(
        _removeFromThrottleCache(options.apiKey),
        options.lookupThrottleDuration * 60 * 1000
      );
      // false here indicates that the throttle warning message has not been shown to the user yet
      throttleCache.set(options.apiKey, false);
    }

    if (options.warnOnLookupLimit) {
      cb('API Lookup Limit Reached');
    } else if (options.warnOnThrottle) {
      throttleCache.set(options.apiKey, true);
      cb(`Throttling lookups for ${options.lookupThrottleDuration} minute`, []);
    } else {
      cb(null, { __keyLimitReached: true });
    }

    return;
  }

  if (response.statusCode === 403 || response.statusCode === 401) {
    cb('You do not have permission to access GTI.  Validate your API key.');
    return;
  }

  // 404 is returned if the entity has no result at all
  if (response.statusCode === 404) return cb();

  if (response.statusCode !== 200) {
    if (body) {
      cb(body);
    } else {
      cb(
        _createJsonErrorPayload(
          response.statusMessage,
          null,
          response.statusCode,
          '2A',
          'GTI HTTP Request Failed',
          {
            response: response,
            body: body
          }
        )
      );
    }
    return;
  }

  cb(null, body);
}

function _lookupHash(hashesArray, entityLookup, options, done) {
  if (doLookupLogging) {
    debugLookupStats.hashLookups++;
  }

  async.mapLimit(
    hashesArray,
    10,
    (hashValue, next) => {
      let requestOptions = {
        uri: `${LOOKUP_URI_BY_TYPE.hash}/${hashValue}`,
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      };
      requestWithDefaults(requestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
          if (err) {
            Logger.error(err, 'Error Looking up Hash');
            return next(err);
          }

          const formattedResult = _processLookupItem(
            'file',
            body,
            entityLookup[fp.toLower(hashValue)],
            options[TYPES_BY_SHOW_NO_DETECTIONS.hash],
            options.showNoInfoTag
          );

          next(null, formattedResult);
        });
      });
    },
    (err, results) => {
      if (err) return done(err);

      done(null, compact(results));
    }
  );
}

function _lookupUrl(entity, options, done) {
  if (doLookupLogging) debugLookupStats.urlLookups++;

  const urlAsBase64WithoutPadding = Buffer.from(entity.value)
    .toString('base64')
    .replace(/=+$/, '');

  let requestOptions = {
    uri: `${LOOKUP_URI_BY_TYPE.url}/${urlAsBase64WithoutPadding}`,
    method: 'GET',
    headers: { 'x-apikey': options.apiKey }
  };

  Logger.debug({ requestOptions }, 'Request Options for URL Lookup');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Looking up URL');
        return done(err);
      }

      const lookupResult = _processLookupItem(
        'url',
        result,
        entity,
        options[TYPES_BY_SHOW_NO_DETECTIONS.url],
        options.showNoInfoTag
      );

      done(null, lookupResult);
    });
  });
}

// Start Google Threat Intelligence
const _lookupVulnerabilities = (entity, options, done) => {
  Logger.trace({ entity }, 'Searching Vulnerabilities');

  const requestOptions = {
    url: `https://www.virustotal.com/api/v3/collections`,
    qs: {
      filter: `name:"${entity.value}" AND collection_type:vulnerability`,
      relationships: 'subscription_preferences,owner,malware_families,threat_actors',
      limit: GTI_LOOKUP_LIMIT
    },
    headers: { 'x-apikey': options.apiKey },
    json: true
  };

  Logger.trace({ requestOptions }, 'Request Options');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Searching Vulnerabilities');
        return done(err);
      }
      if (!get('data.length', result)) return done(null, { entity, data: null });

      Logger.trace({ result }, 'Result of Vulnerabilities Lookup');

      const vulnerabilitiesLookupResult = {
        entity,
        data: {
          summary: [`Vulns: ${result.data.length}`],
          details: {
            vulnerabilities: flow(get('data'), map('attributes'))(result)
          }
        }
      };

      done(null, vulnerabilitiesLookupResult);
    });
  });
};

const _lookupThreatActors = (entity, options, done) => {
  Logger.trace({ entity }, 'Searching Threat Actors');

  const requestOptions = {
    url: `https://www.virustotal.com/api/v3/collections`,
    qs: {
      filter: `name:"${entity.value}" AND collection_type:threat-actor`,
      relationships: 'subscription_preferences,owner,malware_families,threat_actors',
      limit: GTI_LOOKUP_LIMIT
    },
    headers: { 'x-apikey': options.apiKey },
    json: true
  };

  Logger.trace({ requestOptions }, 'Request Options');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Searching Threat Actors');
        return done(err);
      }
      if (!get('data.length', result)) return done(null, { entity, data: null });

      Logger.trace({ result }, 'Result of Threat Actors Lookup');

      const threatActorsLookupResult = {
        entity,
        data: {
          summary: [`Threat Actors: ${get('data.length', result)}`],
          details: {
            threatActors: flow(get('data'), map('attributes'))(result)
          }
        }
      };

      done(null, threatActorsLookupResult);
    });
  });
};

const _lookupThreats = (entity, options, done) => {
  Logger.trace({ entity }, 'Searching Threats');

  const { route, queryParams } = getGtiRequestOptionsByType(entity, 'associations');

  const requestOptions = {
    url: `https://www.virustotal.com/api/v3/${route}`,
    ...(queryParams && { qs: queryParams }),
    headers: { 'x-apikey': options.apiKey },
    json: true
  };

  Logger.trace({ requestOptions }, 'Request Options');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Searching Threats');
        return done(err);
      }
      if (!get('data.length', result))
        return done(null, { entity, threats: [], threatsCount: 0, threatsCursor: '' });

      Logger.trace({ result }, 'Result of Threats Lookup');

      const formattedThreats = flow(
        get('data'),
        map((threat) => ({
          ...threat.attributes,
          id: threat.id,
          relationships: threat.relationships,
          motivationNames: map('value', threat.attributes.motivations),
          targetedIndustryNames: map(
            ({ industry_group, industry }) =>
              size(industry_group) > size(industry) ? industry_group : industry,
            threat.attributes.targeted_industries_tree
          ),
          targetedRegionNames: flow(
            map((region) =>
              region.country || region.country_iso2 || region.sub_region || region.region
                ? `${region.country || region.country_iso2}${
                    (region.country || region.country_iso2) &&
                    (region.sub_region || region.region)
                      ? ', '
                      : ''
                  }${region.sub_region || region.region}`
                : null
            ),
            compact
          )(threat.attributes.targeted_regions_hierarchy),
          htmlDescription: convertMarkdownToHtml(threat.attributes.description),
          confidenceGroupedData: groupByConfidence(threat.attributes),
          categorizedIocs: flattenWithPaths(entity, threat.attributes.aggregations),
          creation_date: threat.attributes.creation_date
            ? threat.attributes.creation_date * 1000
            : threat.attributes.creation_date,
          last_modification_date: threat.attributes.last_modification_date
            ? threat.attributes.last_modification_date * 1000
            : threat.attributes.last_modification_date
        }))
      )(result);

      done(null, {
        entity,
        threats: formattedThreats,
        threatsCount: get('meta.count', result),
        threatsCursor: get('meta.cursor', result)
      });
    });
  });
};

const _lookupReports = (entity, options, done) => {
  Logger.trace({ entity }, 'Searching Reports');

  const { route, queryParams } = getGtiRequestOptionsByType(entity, 'reports');

  const requestOptions = {
    url: `https://www.virustotal.com/api/v3/${route}`,
    ...(queryParams && { qs: queryParams }),
    headers: { 'x-apikey': options.apiKey },
    json: true
  };

  Logger.trace({ requestOptions }, 'Request Options');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error(err, 'Error Searching Reports');
        return done(err);
      }
      if (!get('data.length', result))
        return done(null, { entity, reports: [], reportsCount: 0, reportsCursor: '' });

      Logger.trace({ result }, 'Result of Reports Lookup');

      const reports = flow(
        get('data'),
        map((report) => ({
          ...report.attributes,
          id: report.id,
          relationships: report.relationships,
          htmlDescription: convertMarkdownToHtml(report.attributes.description),
          targetedIndustryNames: map(
            ({ industry_group, industry }) =>
              size(industry_group) > size(industry) ? industry_group : industry,
            report.attributes.targeted_industries_tree
          ),
          targetedRegionNames: flow(
            map((region) =>
              region.country || region.country_iso2 || region.sub_region || region.region
                ? `${region.country || region.country_iso2}${
                    (region.country || region.country_iso2) &&
                    (region.sub_region || region.region)
                      ? ', '
                      : ''
                  } ${region.sub_region || region.region}`
                : null
            ),
            compact
          )(report.attributes.targeted_regions_hierarchy),
          confidenceGroupedData: groupByConfidence(report.attributes),
          categorizedIocs: flattenWithPaths(entity, report.attributes.aggregations),
          creation_date: report.attributes.creation_date
            ? report.attributes.creation_date * 1000
            : report.attributes.creation_date,
          last_modification_date: report.attributes.last_modification_date
            ? report.attributes.last_modification_date * 1000
            : report.attributes.last_modification_date
        }))
      )(result);

      done(null, {
        entity,
        reports,
        reportsCount: get('meta.count', result),
        reportsCursor: get('meta.cursor', result)
      });
    });
  });
};

const queryParams = {
  limit: GTI_LOOKUP_LIMIT,
  relationships: 'subscription_preferences,owner,malware_families,threat_actors'
};

const getGtiRequestOptionsByType = (entity, relationship) =>
  ({
    IPv4: {
      route: `ip_addresses/${entity.value}/${relationship}`,
      queryParams
    },
    domain: {
      route: `domains/${entity.value}/${relationship}`,
      queryParams
    },
    url: {
      route: `urls/${entity.value}/${relationship}`,
      queryParams
    },
    hash: {
      route: `files/${entity.value}/${relationship}`,
      queryParams
    }
  }[entity.isHash ? 'hash' : entity.type]);

const getUiUrlByEntityType = (entity) =>
  ({
    IPv4: `ip-address/${entity.value}/associations`,
    domain: `domain/${entity.value}/associations`,
    url: `url/${entity.value}/associations`,
    hash: `file/${entity.value}/associations`
  }[entity.isHash ? 'hash' : entity.type]);

const groupByConfidence = (threat) => {
  const groupedMotivations = groupBy('confidence', threat.motivations);
  const groupedTags = groupBy('confidence', threat.tags_details);
  const groupedMalwareRoles = groupBy('confidence', threat.malware_roles);
  const groupedAvailableMitigation = groupBy('confidence', threat.available_mitigation);
  const groupedVendorFixReferences = groupBy('confidence', threat.vendor_fix_references);
  const groupedSourceRegions = groupBy('confidence', threat.source_regions_hierarchy);
  const groupedTargetedRegions = groupBy('confidence', threat.targeted_regions_hierarchy);
  const groupedTargetedIndustries = groupBy(
    'confidence',
    threat.targeted_industries_tree
  );

  const uniqueConfidences = flow(
    assign(groupedMotivations),
    assign(groupedTags),
    assign(groupedMalwareRoles),
    assign(groupedAvailableMitigation),
    assign(groupedVendorFixReferences),
    assign(groupedSourceRegions),
    assign(groupedTargetedRegions),
    assign(groupedTargetedIndustries),
    mapValues((val) => (isEmpty(val) ? undefined : val)),
    omitBy(isUndefined),
    keys,
    uniq
  )({});

  if (!size(uniqueConfidences)) return;

  const threatsGroupedByConfidence = reduce(
    (agg, confidence) => {
      const getUniqueValuesInGroup = flow(
        get(confidence),
        map('value'),
        uniq,
        filter((x) => !['null', null, 'undefined', undefined].includes(x)),
        compact
      );

      const formatRegion = flow(
        get(confidence),
        map(
          (region) =>
            `${region.country || region.country_iso2}${
              (region.country || region.country_iso2) &&
              (region.sub_region || region.region)
                ? ', '
                : ''
            } ${region.sub_region || region.region}`
        ),
        uniq,
        filter((x) => !['null', null, 'undefined', undefined].includes(x)),
        compact
      );

      const motivationsContent = getUniqueValuesInGroup(groupedMotivations);
      const motivations = size(motivationsContent) && {
        motivations: motivationsContent
      };

      const tags = size(groupedTags) && { tags: getUniqueValuesInGroup(groupedTags) };

      const malwareRolesContent = getUniqueValuesInGroup(groupedMalwareRoles);
      const malwareRoles = size(malwareRolesContent) && {
        malwareRoles: malwareRolesContent
      };
      const availableMitigationContent = getUniqueValuesInGroup(groupedMalwareRoles);
      const availableMitigation = size(availableMitigationContent) && {
        availableMitigation: availableMitigationContent
      };
      const vendorFixReferencesContent = getUniqueValuesInGroup(groupedMalwareRoles);
      const vendorFixReferences = size(vendorFixReferencesContent) && {
        vendorFixReferences: vendorFixReferencesContent
      };

      const sourceRegionsContent = formatRegion(groupedSourceRegions);
      const sourceRegions = size(sourceRegionsContent) && {
        sourceRegions: sourceRegionsContent
      };

      const targetedRegionsContent = formatRegion(groupedTargetedRegions);
      const targetedRegions = size(targetedRegionsContent) && {
        targetedRegions: targetedRegionsContent
      };

      const targetedIndustriesContent = flow(
        get(confidence),
        map(({ industry_group, industry }) =>
          size(industry_group) > size(industry) ? industry_group : industry
        ),
        uniq,
        compact
      )(groupedTargetedIndustries);

      const targetedIndustries = size(targetedIndustriesContent) && {
        targetedIndustries: targetedIndustriesContent
      };

      return {
        ...agg,
        [confidence]: {
          ...motivations,
          ...tags,
          ...malwareRoles,
          ...availableMitigation,
          ...vendorFixReferences,
          ...sourceRegions,
          ...targetedRegions,
          ...targetedIndustries
        }
      };
    },
    {},
    uniqueConfidences
  );

  return threatsGroupedByConfidence;
};

const flattenWithPaths = (entity, obj) => {
  const traverse = curry((path, val) => {
    const isPlainObjectWithNoNested =
      isPlainObject(val) && !some((v) => isPlainObject(v) || isArray(v), values(val));

    if (isPlainObjectWithNoNested) return [{ ...val, path: path.join('.') }];

    const isArrayWithNoNested =
      isArray(val) && !some((v) => isPlainObject(v) || isArray(v), val);

    if (isArrayWithNoNested) return [{ values: val, path: path.join('.') }];

    const isPlainObjectWithNested =
      isPlainObject(val) && some((v) => isPlainObject(v) || isArray(v), values(val));

    if (isPlainObjectWithNested) {
      return flow(
        toPairs,
        flatMap(([key, value]) => traverse([...path, key], value))
      )(val);
    }
    const isArrayWithNested =
      isArray(val) && some((v) => isPlainObject(v) || isArray(v), val);

    if (isArrayWithNested) {
      return flow(
        entries,
        flatMap(([_, value]) => traverse([...path], value))
      )(val);
    }

    const valueNotObjectOrArrayResult = [{ value: val, path: path.join('.') }];

    return valueNotObjectOrArrayResult;
  });

  const flattenedListOfObjects = traverse([], obj);

  const sortedListOfValues = sortByEntityPresenceAndPrevalence(
    entity,
    flattenedListOfObjects
  );

  return sortedListOfValues;
};

const sortByEntityPresenceAndPrevalence = (entity, arrayOfObjects) =>
  flow(
    compact,
    uniqBy('value'),
    map((obj) => ({
      ...obj,
      readablePath: makeHumanReadable(obj.path),
      matchesSubstring: hasSubstringInValue(obj, entity.value)
    })),
    sortBy((obj) => -(obj.prevalence || 0)),
    sortBy((obj) => (obj.matchesSubstring ? 0 : 1)),
    groupBy('readablePath')
  )(arrayOfObjects);

const hasSubstringInValue = ({ value: val }, substring) =>
  includes(substring.toLowerCase(), (isString(val) ? val : String(val)).toLowerCase());

const makeHumanReadable = flow(replace(/\./g, ' '), replace(/_/g, ' '), startCase);
// End Google Threat Intelligence

const _processLookupItem = (
  type,
  result,
  entity,
  showEntitiesWithNoDetections,
  showNoInfoTag
) => {
  if (result && result.__keyLimitReached) {
    return {
      entity,
      data: null
    };
  }

  const data = fp.get('data', result);
  const attributes = fp.get('attributes', data);
  const lastAnalysisStats = fp.get('last_analysis_stats', attributes);
  const totalResults = fp.flow(
    fp.pick(['undetected', 'malicious', 'suspicious', 'harmless']),
    fp.values,
    fp.sum
  )(lastAnalysisStats);
  const totalMalicious = fp.get('malicious', lastAnalysisStats);

  // Check for no data
  // If there is no data, then VT does not know anything about the entity in question)
  if (!result || !data || !totalResults) {
    // if `showNoInfoTag` is true, then the user wants to see a result everytime
    // indicating that there is no information in VT
    if (showNoInfoTag) {
      return {
        entity,
        data: {
          summary: ['has not seen or scanned'],
          details: {
            noInfoMessage: true
          }
        }
      };
    } else {
      // The user does not want to see misses so we return a normal miss result
      return {
        entity,
        data: null
      };
    }
  }

  // If there are no positive detections and the user has hidden results with zero positive detections
  // return a miss
  if (!totalMalicious && !showEntitiesWithNoDetections) {
    return {
      entity,
      data: null
    };
  }

  const scans = fp.flow(
    fp.get('last_analysis_results'),
    map((scanResult, scanName) => ({
      name: scanName,
      detected: scanResult.category === 'malicious',
      result:
        !scanResult.result && scanResult.category === 'type-unsupported'
          ? 'type-unsupported'
          : ['clean', 'suspicious', 'malware', 'malicious', 'unrated'].includes(
              scanResult.result
            )
          ? fp.capitalize(scanResult.result)
          : scanResult.result
    }))
  )(attributes);

  const coreLink = `https://www.virustotal.com/gui/${fp.replace('_', '-', data.type)}/${
    data.id
  }`;

  const detailsTab = getDetailFields(DETAILS_FORMATS[type], attributes);

  return {
    entity,
    data: {
      summary: [
        ...fp.flow(
          fp.filter(fp.get('detected')),
          fp.map(fp.get('result')),
          fp.uniq,
          fp.slice(0, 3)
        )(scans)
      ],
      details: {
        type,
        detectionsLink: `${coreLink}/detection`,
        relationsLink: `${coreLink}/relations`,
        detailsLink: `${coreLink}/details`,
        communityLink: `${coreLink}/community`,
        behaviorLink: `${coreLink}/behavior`,
        total: totalResults,
        reputation: attributes.reputation,
        scan_date: new Date(attributes.last_modification_date * 1000),
        positives: totalMalicious,
        positiveScans: fp.flow(
          fp.filter(fp.get('detected')),
          fp.orderBy('result', 'desc')
        )(scans),
        names: attributes.names,
        negativeScans: fp.flow(
          fp.filter(({ detected }) => !detected),
          fp.orderBy('result', 'desc')
        )(scans),
        detailsTab,
        tags: attributes.tags
      }
    }
  };
};

const DETAILS_FORMATS = {
  file: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'File type', path: 'type_description' },
    {
      key: 'File size',
      path: 'size',
      transformation: (size) => `${~~(size / 1049295 / 0.01) * 0.01} MB (${size} bytes)`
    },
    { key: 'MD5', path: 'md5' },
    { key: 'SHA-1', path: 'sha1' },
    { key: 'SHA-256', path: 'sha256' },
    { key: 'Vhash', path: 'vhash' },
    { key: 'Authentihash', path: 'authentihash' },
    { key: 'Imphash', path: 'pe_info.imphash' },
    { key: 'Rich PE header hash', path: 'pe_info.rich_pe_header_hash' },
    { key: 'SSDEEP', path: 'ssdeep' },
    { key: 'TLSH', path: 'tlsh' },
    { key: 'Magic', path: 'magic' },
    {
      key: 'TrID',
      path: 'trid',
      isList: true,
      transformation: fp.map((trid) => `${trid.file_type} (${trid.probability}%)`)
    },
    { key: 'PEiD', path: 'packers.PEiD' }
  ],
  url: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Final URL', path: 'last_final_url' },
    { key: 'Status Code', path: 'last_http_response_code' },
    {
      key: 'Body Length',
      path: 'last_http_response_content_length',
      transformation: (size) => `${size} B`
    },
    { key: 'Body SHA-256', path: 'last_http_response_content_sha256' },
    {
      key: 'Categories',
      path: 'categories',
      isObject: true
    },
    {
      key: 'Headers',
      path: 'last_http_response_headers',
      isObject: true
    }
  ],
  domain: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Reputation', path: 'reputation' },
    { key: 'Registrar', path: 'registrar' },
    { key: 'Last Modified', path: 'last_modification_date', isDate: true },
    {
      key: 'Last DNS Records',
      path: 'last_dns_records',
      isObject: true,
      transformation: fp.reduce(
        (agg, record) => ({
          ...agg,
          [`Type - ${record.type}`]: `${record.value} (TTL ${record.ttl})`
        }),
        {}
      )
    },
    {
      key: 'Categories',
      path: 'categories',
      isObject: true
    }
  ],
  ip: [
    { key: 'Basic Properties', isTitle: true },
    { key: 'Network', path: 'network' },
    { key: 'Autonomous System Number', path: 'asn' },
    { key: 'Autonomous System Label', path: 'as_owner' },
    { key: 'Regional Internet Registry', path: 'regional_internet_registry' },
    { key: 'Country', path: 'country' },
    { key: 'Continent', path: 'continent' }
  ]
};

const getDetailFields = (detailFields, attributes) =>
  fp.map((detailField) => {
    const value = fp.get(detailField.path, attributes);
    const transformedValue = detailField.transformation
      ? detailField.transformation(value)
      : value;

    return {
      ...detailField,
      ...(value && {
        value: transformedValue
      })
    };
  }, detailFields);

function _lookupEntityType(type, entity, options, done) {
  if (doLookupLogging) debugLookupStats[`${type}Lookups`]++;

  let requestOptions = {
    uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}`,
    method: 'GET',
    headers: { 'x-apikey': options.apiKey }
  };

  Logger.debug({ requestOptions }, 'Request Options for Type detections Lookup');

  requestWithDefaults(requestOptions, function (err, response, body) {
    _handleRequestError(err, response, body, options, function (err, result) {
      if (err) {
        Logger.error({ err, result, type: _.startCase(type) }, 'Search Failed');
        return _.get(err, 'error.message', '').includes('is not a valid domain pattern')
          ? done(null, [])
          : done(err);
      }

      let lookupResults = _processLookupItem(
        type,
        result,
        entity,
        options[TYPES_BY_SHOW_NO_DETECTIONS[type]],
        options.showNoInfoTag
      );

      if (!fp.get('data.details', lookupResults)) return done();

      done(null, lookupResults);
    });
  });
}

function parseBaselineInvestigationThreshold(bti) {
  const rules = bti.split(',');
  const compiledRules = [];
  rules.forEach((rule) => {
    const parts = rule.split(':');
    if (parts.length !== 2 && parts.length !== 3) {
      throw `Invalid rule [${rule}]. Rule must be of the format <range>:<message> or <range>:<level>:<message>`;
    }
    let range, level, message;
    range = splitBtiRange(rule, parts[0]);

    if (parts.length === 3) {
      level = parts[1].trim();
      message = parts[2].trim();
    } else {
      level = 'none';
      message = parts[1].trim();
    }

    if (level !== 'warn' && level !== 'danger' && level !== 'none') {
      throw `Invalid rule [${rule}]. Level [${level}] must be either "warn" or "danger".`;
    }

    compiledRules.push({
      message,
      level,
      ...range
    });
  });
  return compiledRules;
}

/**
 * Takes a range in the format `<number>-<number>` and turns it into a range object
 * of the form:
 * ```
 * {
 *   min: <number>,
 *   max: <number>
 * }
 * ```
 * @param range
 * @returns {{min: number, max: number}}
 */
function splitBtiRange(rule, range) {
  let ranges = range.split('-');
  if (ranges.length !== 1 && ranges.length !== 2) {
    throw `Invalid range [${range}] on rule [${rule}].  Range must be a single number or a range of the format <number>-<number>`;
  }

  if (isNaN(ranges[0])) {
    throw `Invalid range [${range}] on rule [${rule}]. The value [${ranges[0]}] must be a number`;
  }

  if (ranges.length === 1) {
    return {
      min: +ranges[0],
      max: +ranges[0]
    };
  }
  if (ranges.length === 2) {
    if (isNaN(ranges[1])) {
      throw `Invalid range [${range}] on rule [${rule}]. The value [${ranges[1]}] must be a number`;
    }
    if (+ranges[0] > +ranges[1]) {
      throw `Invalid range [${range}] on rule [${rule}]. The value [${ranges[0]}] must be greater than the value [${ranges[1]}]`;
    }
    return {
      min: +ranges[0],
      max: +ranges[1]
    };
  }
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'VIRUSTOTAL_' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

async function getWhois(entity, options) {
  return new Promise((resolve, reject) => {
    if (entity.isIP || entity.isDomain) {
      const type = entity.isIP ? 'ip' : 'domain';
      const relationsWhoIsRequestOptions = {
        uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}/historical_whois`,
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      };

      Logger.debug(
        { relationsWhoIsRequestOptions },
        'Request Options for Type historical_whois Relations Lookup'
      );

      requestWithDefaults(relationsWhoIsRequestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, whoIsResult) {
          if (err) {
            Logger.error(err, `Error Looking up ${_.startCase(type)}`);
            return reject(err);
          }

          if (whoIsResult.data) {
            const historicalWhoIs = fp.flow(
              fp.getOr([], 'data'),
              fp.reduce((accum, whoIsLookup) => {
                // filter out DNS entries with no results.  We check for this
                // by looking for a last_updated value that is null
                if (fp.get('attributes.last_updated', whoIsLookup)) {
                  accum.push({
                    last_updated: fp.flow(
                      fp.get('attributes.last_updated'),
                      (x) => new Date(x * 1000)
                    )(whoIsLookup),
                    ...fp.get('attributes.whois_map', whoIsLookup)
                  });
                }
                return accum;
              }, [])
            )(whoIsResult);

            resolve(historicalWhoIs);
          } else {
            resolve([]);
          }
        });
      });
    } else {
      resolve([]);
    }
  });
}

/**
 * Fetches additional relations data for domains and IP entity types
 *
 * @param entity
 * @param options
 */
async function getRelations(entity, options) {
  return new Promise((resolve, reject) => {
    if (entity.isIP || entity.isDomain) {
      const type = entity.isIP ? 'ip' : 'domain';

      let relationsRefFilesRequestOptions = {
        uri: `${LOOKUP_URI_BY_TYPE[type]}/${entity.value}/referrer_files`,
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      };

      Logger.debug(
        { relationsRefFilesRequestOptions },
        'Request Options for Type referrer_files Relations Lookup'
      );

      requestWithDefaults(
        relationsRefFilesRequestOptions,
        function (err, response, body) {
          _handleRequestError(
            err,
            response,
            body,
            options,
            function (err, refFilesResult) {
              if (err) {
                Logger.error(err, `Error Looking up ${_.startCase(type)}`);
                return reject(err);
              }

              if (refFilesResult.data) {
                const referenceFiles = fp.flow(
                  fp.getOr([], 'data'),
                  fp.map((referenceFile) => ({
                    link:
                      referenceFile.attributes &&
                      `https://www.virustotal.com/gui/${referenceFile.type}/${referenceFile.id}/detection`,
                    name: fp.getOr(
                      referenceFile.id,
                      'attributes.meaningful_name',
                      referenceFile
                    ),
                    type: fp.getOr(
                      referenceFile.type,
                      'attributes.type_tag',
                      referenceFile
                    ),
                    detections: referenceFile.attributes
                      ? `${fp.getOr(
                          0,
                          'attributes.last_analysis_stats.malicious',
                          referenceFile
                        )} / ${fp.getOr(
                          0,
                          'attributes.last_analysis_stats.undetected',
                          referenceFile
                        )}`
                      : '-',
                    scannedDate: fp.flow(
                      fp.getOr('-', 'attributes.last_analysis_date'),
                      (x) => new Date(x * 1000)
                    )(referenceFile)
                  }))
                )(refFilesResult);
                resolve(referenceFiles);
              } else {
                resolve([]);
              }
            }
          );
        }
      );
    } else {
      resolve([]);
    }
  });
}

function getBehaviors(entity, options) {
  return new Promise((resolve, reject) => {
    if (entity.isMD5 || entity.isSHA1 || entity.isSHA256) {
      let behaviourSummaryOptions = {
        uri: `https://www.virustotal.com/api/v3/files/${entity.value}/behaviour_summary`,
        method: 'GET',
        headers: { 'x-apikey': options.apiKey }
      };

      requestWithDefaults(behaviourSummaryOptions, (err, response, body) => {
        _handleRequestError(err, response, body, options, (err, result) => {
          if (err) {
            Logger.error(err, `Error Looking up ${entity.type}`);
            return reject(err);
          }

          if (result.data) {
            resolve(result.data);
          } else {
            resolve([]);
          }
        });
      });
    } else {
      resolve([]);
    }
  });
}

function startup(logger) {
  Logger = logger;

  if (config && config.logging && config.logging.logLookupStats) {
    Logger.info({ loggerLevel: Logger._level }, 'Will do Lookup Logging');
    doLookupLogging = true;
    lookupHashSet = new Set();
    lookupIpSet = new Set();
    lookupDomainSet = new Set();
    lookupUrlSet = new Set();
    lookupCveSet = new Set();
    // Print log every hour
    setInterval(_logLookupStats, 60 * 60 * 1000);
  } else {
    doLookupLogging = false;
    Logger.info({ loggerLevel: Logger._level }, 'Will not do Lookup Logging');
  }

  pendingLookupCache = new PendingLookupCache(logger);
  if (config && config.settings && config.settings.trackPendingLookups) {
    pendingLookupCache.setEnabled(true);
  }

  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === 'string' &&
    config.request.passphrase.length > 0
  ) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  defaults.json = true;

  requestWithDefaults = request.defaults(defaults);
}

function _logLookupStats() {
  debugLookupStats.ipCount = lookupIpSet.size;
  debugLookupStats.domainCount = lookupDomainSet.size;
  debugLookupStats.urlCount = lookupUrlSet.size;
  debugLookupStats.cveCount = lookupCveSet.size;
  debugLookupStats.hashCount = lookupHashSet.size;

  Logger.info(debugLookupStats, 'Unique Entity Stats');

  if (debugLookupStats.hourCount == 23) {
    lookupHashSet.clear();
    lookupIpSet.clear();
    lookupDomainSet.clear();
    lookupUrlSet.clear();
    lookupCveSet.clear();
    debugLookupStats.hourCount = 0;
    debugLookupStats.hashCount = 0;
    debugLookupStats.ipCount = 0;
    debugLookupStats.ipLookups = 0;
    debugLookupStats.domainCount = 0;
    debugLookupStats.domainLookups = 0;
    debugLookupStats.urlCount = 0;
    debugLookupStats.cveCount = 0;
    debugLookupStats.urlLookups = 0;
    debugLookupStats.hashLookups = 0;
    debugLookupStats.dayCount++;
  } else {
    debugLookupStats.hourCount++;
  }
}

function errorToPojo(err) {
  if (err instanceof Error) {
    return {
      // Pull all enumerable properties, supporting properties on custom Errors
      ...err,
      // Explicitly pull Error's non-enumerable properties
      name: err.name,
      message: err.message,
      stack: err.stack,
      detail: err.detail ? err.detail : 'Google compute engine had an error'
    };
  }
  return err;
}

async function onMessage(payload, options, cb) {
  const { entity, action } = payload;
  switch (action) {
    case 'GET_RELATIONS':
      try {
        const relations = await getRelations(entity, options);
        Logger.trace({ relations }, 'GET_RELATIONS');
        cb(null, relations);
      } catch (error) {
        cb(error);
      }
      break;
    case 'GET_BEHAVIORS':
      try {
        const behaviors = await getBehaviors(entity, options);
        Logger.trace({ behaviors }, 'GET_BEHAVIORS');
        cb(null, behaviors);
      } catch (error) {
        cb(error);
      }
      break;
    case 'GET_WHOIS':
      try {
        const whois = await getWhois(entity, options);
        Logger.trace({ whois }, 'GET_WHOIS');
        cb(null, whois);
      } catch (error) {
        cb(error);
      }
      break;
  }
}

async function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiKey.value !== 'string' ||
    (typeof userOptions.apiKey.value === 'string' &&
      userOptions.apiKey.value.length === 0)
  ) {
    errors.push({
      key: 'apiKey',
      message: 'You must provide a GTI API key'
    });
  }

  let maxHashesPerGroup = userOptions.maxHashesPerGroup.value;
  if (_.isNaN(maxHashesPerGroup) || maxHashesPerGroup <= 0) {
    errors.push({
      key: 'maxHashesPerGroup',
      message: 'Maximum number of hashes per lookup request must be greater than 0'
    });
  }

  try {
    parseBaselineInvestigationThreshold(userOptions.baselineInvestigationThreshold.value);
  } catch (e) {
    Logger.error(e);
    errors.push({
      key: 'baselineInvestigationThreshold',
      message: e.toString()
    });
  }

  // if (!errors.length) {
  //   try {
  //     if (job) job.cancel();

  //     job = schedule.scheduleJob(`0 */24 * * *`, getAndCacheAllThreatActorNames(options));
  //   } catch (_) {}
  // }

  cb(null, errors);
}

const getAndCacheAllThreatActorNames =
  (options, cursor, agg = []) =>
  async () => {
    const searchResult = get(
      'body',
      await asyncRequestWithDefaults(
        {
          uri: 'https://www.virustotal.com/api/v3/collections',
          qs: {
            filter: `collection_type:threat-actor`,
            attributes: 'name',
            limit: 40,
            ...(cursor && { cursor })
          }
        },
        options
      )
    );

    const threatActorNames = flow(get('data'), map('attributes.name'))(searchResult);

    const nextCursor = get('meta.cursor', searchResult);
    const nextAgg = agg.concat(threatActorNames);

    if (nextCursor) {
      return getAndCacheAllThreatActorNames(options, nextCursor, nextAgg);
    }

    threatActorNames = flow(
      uniq,
      sortBy((name) => name.toLowerCase())
    )(nextAgg);
  };

const asyncRequestWithDefaults = (requestOptions, options) =>
  new Promise((resolve, reject) =>
    requestWithDefaults(
      {
        ...requestOptions,
        headers: {
          ...requestOptions.headers,
          'x-apikey': get('apiKey.value', options) || options.apiKey
        },
        json: true
      },
      (err, response) => {
        if (err) {
          reject(err);
        } else {
          resolve(response);
        }
      }
    )
  );

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
