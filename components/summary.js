/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  verdict: Ember.computed.alias('details.verdict'),
  threatScore: Ember.computed.alias('details.gtiAssessment.threat_score.value'),
  threatsCount: Ember.computed.alias('details.threatsCount'),
  reportsCount: Ember.computed.alias('details.reportsCount'),
});
