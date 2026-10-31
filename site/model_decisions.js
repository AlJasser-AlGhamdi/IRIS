(function exposeAiDecisionRule(root) {
  root.isAiDecision = (call) => call?.role === "parse" || call?.role === "choose";
})(globalThis);
