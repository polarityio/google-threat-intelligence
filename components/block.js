polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  verdict: Ember.computed.alias('details.verdict'),
  threatScore: Ember.computed.alias('details.gtiAssessment.threat_score.value'),
  threats: Ember.computed.alias('details.threats'),
  threatsCount: Ember.computed.alias('details.threatsCount'),
  reports: Ember.computed.alias('details.reports'),
  reportsCount: Ember.computed.alias('details.reportsCount'),
  vulnerabilities: Ember.computed.alias('details.vulnerabilities'),
  threatActors: Ember.computed.alias('details.threatActors'),
  associationLink: Ember.computed.alias('details.associationLink'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  maxResolutionsToShow: 20,
  associationTab: 'threats',
  expandedAssociations: Ember.computed.alias('block._state.expandedAssociations'),
  expandedVulnerabilities: Ember.computed.alias('block._state.expandedVulnerabilities'),
  iconNamesByAssociationType: {
    report: 'file-alt',
    campaign: 'bullseye',
    collection: 'layer-group',
    'malware-family': 'bug',
    'software-toolkit': 'tools',
    vulnerability: 'lock',
    'threat-actor': 'theater-masks'
  },
  maxUrlsToShow: 20,
  showScanResults: false,
  showFilesReferring: false,
  showCopyMessage: false,
  showHistoricalWhois: false,
  expandedWhoisMap: Ember.computed.alias('block.data.details.expandedWhoisMap'),
  domainVirusTotalLink: '',
  numUrlsShown: 0,
  numResolutionsShown: 0,
  whoIsIpKeys: [
    { key: 'origin' },
    { key: 'role' },
    { key: 'mnt-by' },
    { key: 'admin-c' },
    { key: 'netname' },
    { key: 'NetType' },
    { key: 'address' },
    { key: 'inetnum' },
    { key: 'Ref' },
    { key: 'Parent' },
    { key: 'Nedivange' },
    { key: 'Updated Date', isDate: true },
    { key: 'OrgId' },
    { key: 'OrgAbuseName' },
    { key: 'OrgAbusePhone' },
    { key: 'OrgTechRef' },
    { key: 'OrgTechHandle' },
    { key: 'OrgAbuseRef' },
    { key: 'City' },
    { key: 'StateProv' },
    { key: 'Address' }
  ],
  whoIsDomainKeys: [
    { key: 'Domain Name' },
    { key: 'Name Server' },
    { key: 'Domain Status' },
    { key: 'DNSSEC' },
    { key: 'Creation Date', isDate: true },
    { key: 'Updated Date' },
    { key: 'Registrant Organization' },
    { key: 'Registrant Country' },
    { key: 'Registrant State/Province' },
    { key: 'Registrant Email' },
    { key: 'Registrar' },
    { key: 'Registrar URL' },
    { key: 'Registrar WHOIS Server' },
    { key: 'Registrar IANA ID' },
    { key: 'Registrar Abuse Contact Phone' },
    { key: 'Registrar Abuse Contact Email' },
    { key: 'Registrar Registration Expiration Date', isDate: true },
    { key: 'Registry Domain ID' },
    { key: 'Registry Expiry Date', isDate: true }
  ],
  activeTab: 'detection',
  scoreGraphicHorizontalOffset: 5,
  scoreGraphicWidth: 100,
  scoreGraphicLineEnd: Ember.computed('scoreGraphicHorizontalOffset', 'scoreGraphicWidth', function () {
    return this.get('scoreGraphicHorizontalOffset') + this.get('scoreGraphicWidth');
  }),
  scoreGraphicTotalWidth: Ember.computed('scoreGraphicWidth', 'scoreGraphicHorizontalOffset', function () {
    return this.get('scoreGraphicWidth') + this.get('scoreGraphicHorizontalOffset') * 2;
  }),
  scoreGraphicValue: Ember.computed('threatScore', 'scoreGraphicHorizontalOffset', 'scoreGraphicWidth', function () {
    const threatScore = this.get('threatScore') || 0;
    const scoreGraphicHorizontalOffset = this.get('scoreGraphicHorizontalOffset') || 0;
    const scoreGraphicWidth = this.get('scoreGraphicWidth') || 0;
    
    return (threatScore / 100) * scoreGraphicWidth + scoreGraphicHorizontalOffset;
  }),
  init() {
    this.set(
      'activeTab',
      this.get('details.scan_date') ||
        this.get('details.reputation') ||
        this.get('details.positiveScans') ||
        this.get('details.positiveScans') === 0
        ? 'detection'
        : 'associations'
    );
    this.set(
      'showScanResults',
      this.get('block.userOptions.showNoDetections') === false
        ? this.get('details.positiveScans.length') < 15
        : this.get('details.total') < 15
    );
    this.set(
      'numUrlsShown',
      Math.min(this.get('maxUrlsToShow'), this.get('details.detectedUrls.length'))
    );
    this.set(
      'numResolutionsShown',
      Math.min(this.get('maxResolutionsToShow'), this.get('details.resolutions.length'))
    );
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.expandedAssociations', {});
      this.set('block._state.expandedVulnerabilities', {});
      this.set('block._state.loadedThreats', false);
      this.set('block._state.loadedReports', false);
    }

    if (this.get('details.names.length') <= 10) {
      this.set('block._state.showNames', true);
    }

    this.set('associationTab', 'threats');

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

    this._super(...arguments);
  },
  getThreats: function () {
    const payload = {
      action: 'GET_THREATS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorThreats', '');
    this.set('block._state.loadingThreats', true);
    this.sendIntegrationMessage(payload)
      .then(({ threatResults, associationLink }) => {
        this.set('block.data.details.threats', threatResults.threats);
        this.set('block.data.details.threatsCount', threatResults.threatsCount);
        this.set('block.data.details.associationLink', associationLink);
        
        this.set('block._state.loadedThreats', true);
        this.get('block').notifyPropertyChange('data');
      })
      .catch((err) => {
        this.set('block._state.errorThreats', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingThreats', false);
      });
  },
  getReports: function () {
    const payload = {
      action: 'GET_REPORTS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorReports', '');
    this.set('block._state.loadingReports', true);
    this.sendIntegrationMessage(payload)
      .then(({ reportResults, associationLink }) => {
        this.set('block.data.details.reports', reportResults.reports);
        this.set('block.data.details.reportsCount', reportResults.reportsCount);
        this.set('block.data.details.associationLink', associationLink);

        this.set('block._state.loadedReports', true);
        this.get('block').notifyPropertyChange('data');
      })
      .catch((err) => {
        this.set('block._state.errorReports', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingReports', false);
      });
  },
  getBehaviors: function () {
    const payload = {
      action: 'GET_BEHAVIORS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorBehaviors', '');
    this.set('block._state.loadingBehaviors', true);
    this.sendIntegrationMessage(payload)
      .then((behaviorSummary) => {
        this.set('block.data.details.behaviorSummary', behaviorSummary);
        this.set(
          'showRegistryKeys',
          typeof this.get('details.behaviorSummary.registry_keys_opened') === 'undefined'
        );
        this.set('showFilesOpened', !this.get('details.behaviorSummary.files_opened'));
        this.set('block._state.loadedBehaviors', true);
      })
      .catch((err) => {
        this.set('block._state.errorBehaviors', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingBehaviors', false);
      });
  },
  getWhois: function () {
    const payload = {
      action: 'GET_WHOIS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorWhois', '');
    this.set('block._state.loadingWhois', true);
    this.sendIntegrationMessage(payload)
      .then((historicalWhoIs) => {
        this.set('block.data.details.historicalWhoIs', historicalWhoIs);
        this.set('expandedWhoisMap', {});
        // If there is no data we expand the whois section automatically
        // to show a "no results" message
        if (historicalWhoIs && historicalWhoIs.length === 0) {
          this.set('showHistoricalWhois', true);
        }
        this.set('block._state.loadedWhois', true);
      })
      .catch((err) => {
        this.set('block._state.errorWhois', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingWhois', false);
      });
  },
  getRelations: function () {
    const payload = {
      action: 'GET_RELATIONS',
      entity: this.get('block.entity')
    };
    this.set('block._state.errorRelations', '');
    this.set('block._state.loadingRelations', true);
    this.sendIntegrationMessage(payload)
      .then((referenceFiles) => {
        this.set('block.data.details.referenceFiles', referenceFiles);
        // If there is no data we expand the whois section automatically
        // to show a "no results" message
        if (referenceFiles && referenceFiles.length === 0) {
          this.set('showFilesReferring', true);
        }
        this.set('block._state.loadedRelations', true);
        this.get('block').notifyPropertyChange('data');
      })
      .catch((err) => {
        this.set('block._state.errorRelations', JSON.stringify(err, null, 4));
      })
      .finally(() => {
        this.set('block._state.loadingRelations', false);
      });
  },
  actions: {
    switchAssociationsTab: function (associationTypeName) {
      this.set('associationTab', associationTypeName);

      if (
        associationTypeName === 'reporting' &&
        !this.get('block._state.loadedReports') &&
        !this.get('block._state.loadingReports')
      ) {
        this.getReports();
      }
    },
    toggleExpandableAssociations: function (associationType, index) {
      this.set(
        `block._state.expandedAssociations.${associationType}${index}`,
        !this.get(`block._state.expandedAssociations.${associationType}${index}`)
      );
    },
    copyData: function () {
      const savedSettings = {
        showScanResults: this.get('showScanResults'),
        showFilesReferring: this.get('showFilesReferring'),
        showHistoricalWhois: this.get('showHistoricalWhois'),
        activeTab: this.get('activeTab'),
        showFilesOpened: this.get('showFilesOpened'),
        showRegistryKeys: this.get('showRegistryKeys'),
        showNames: this.get('block._state.showNames'),
        expandedWhoisMap: Object.assign({}, this.get('expandedWhoisMap'))
      };

      this.set('showScanResults', true);
      this.set('showFilesReferring', true);
      this.set('showHistoricalWhois', true);
      this.set('showFilesOpened', true);
      this.set('showRegistryKeys', true);
      this.set('block._state.showNames', true);
      if (this.get('details.historicalWhoIs')) {
        this.get('details.historicalWhoIs').forEach((whois, index) => {
          this.set(`expandedWhoisMap.${index}`, true);
        });
      }

      Ember.run.scheduleOnce(
        'afterRender',
        this,
        this.copyElementToClipboard,
        `virustotal-container-${this.get('uniqueIdPrefix')}`
      );

      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedSettings);
    },
    /**
     * Change data tab.  valid tab names are:
     * detection
     * details
     * fileNames -- requires fileName data
     * behaviorSummary -- requires behavior data
     * relations -- requires relations and whois data
     * @param tabName
     */
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
      switch (tabName) {
        // relations tab requires relations and whois data
        case 'relations':
          // Make sure we only load the data once
          if (!this.get('block._state.loadedWhois')) {
            this.getWhois();
          }
          if (!this.get('block._state.loadedRelations')) {
            this.getRelations();
          }
          break;
        case 'behaviorSummary':
          if (!this.get('block._state.loadedBehaviors')) {
            this.getBehaviors();
          }
          break;
        case 'associations':
          if (
            !this.get('block._state.loadedThreats') &&
            !this.get('block._state.loadingThreats')
          ) {
            this.getThreats();
          }
          break;
      }
    },
    toggleShowResults: function (resultType) {
      this.toggleProperty(resultType);
    },
    expandWhoIsRow: function (index) {
      this.set(`expandedWhoisMap.${index}`, !this.get(`expandedWhoisMap.${index}`));
    },
    toggleExpandableVulnerabilities: function (section, index) {
      const key = `${section}${index}`;
      if (!this.get('block._state.expandedVulnerabilities')) {
        this.set('block._state.expandedVulnerabilities', {});
      }
      this.set(
        `block._state.expandedVulnerabilities.${key}`,
        !this.get(`block._state.expandedVulnerabilities.${key}`)
      );
    }
  },
  copyElementToClipboard(element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();
    range.selectNode(
      typeof element === 'string' ? document.getElementById(element) : element
    );
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState(savedSettings) {
    const {
      activeTab,
      showFilesReferring,
      showHistoricalWhois,
      showScanResults,
      expandedWhoisMap,
      showRegistryKeys,
      showFilesOpened,
      showNames
    } = savedSettings;
    this.set('showFilesReferring', showFilesReferring);
    this.set('showHistoricalWhois', showHistoricalWhois);
    this.set('showScanResults', showScanResults);
    this.set('activeTab', activeTab);
    this.set('showFilesOpened', showFilesOpened);
    this.set('showRegistryKeys', showRegistryKeys);
    this.set('block._state.showNames', showNames);
    if (this.get('expandedWhoisMap') && expandedWhoisMap) {
      Object.keys(this.get('expandedWhoisMap')).forEach((key) => {
        this.set(`expandedWhoisMap.${key}`, expandedWhoisMap[key] ? true : false);
      });
    }

    this.set('showCopyMessage', true);
    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
