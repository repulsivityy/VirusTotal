var undef;
var riskRatingMap = new Map();
var exploitRatingMap = new Map();
var userInteractionMap = new Map();

var wideArray = [0, 0, 0, 0];
var confirmedArray = [0, 0, 0, 0];
var availableArray = [0, 0, 0, 0];
//var anticipatedArray = [0, 0, 0, 0];
var noknownArray = [0, 0, 0, 0];

var datatable;

var defaultVisibleColumns = ['CveId', 'ExploitRating', 'RiskRating', 'UserInteraction', 'AssociatedActors', 'AssociatedMalware', 'Title', 'V3_BaseScore', 'V3_TemporalScore', 'V2_BaseScore', 'V2_TemporalScore'];
var combinedColumns = ['Score_v3', 'Score_v2'];
var issueConfidenceMap = new Map();

exploitRatingMap.set("wide", "5000");
exploitRatingMap.set("confirmed", "4000");
exploitRatingMap.set("available", "3000");
//exploitRatingMap.set("anticipated", "2000");
exploitRatingMap.set("no known", "1000");
exploitRatingMap.set("not known", "1000");

riskRatingMap.set("critical", "4000");
riskRatingMap.set("high", "3000");
riskRatingMap.set("medium", "2000");
riskRatingMap.set("low", "1000");

userInteractionMap.set("none", "5000");
userInteractionMap.set("required", "1000");

issueConfidenceMap.set("high", "3000");
issueConfidenceMap.set("medium", "2000");
issueConfidenceMap.set("low", "1000");
issueConfidenceMap.set("-", "-1");
issueConfidenceMap.set("confirmed", "3000"); 
issueConfidenceMap.set("potential", "2000");

const blankLiteral = '';
const hyphen = '-';
const titleTerminationLength = 40;
