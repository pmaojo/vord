export default {
  strictMode: true,
  bulletproofBoundaries: {
    enforceUnidirectionalImports: true,
    forbiddenImports: [
      {
        from: 'src/features/*',
        to: 'src/features/*',
        allowSameFeature: true,
        message: 'Cross-feature imports are strictly forbidden under Bulletproof React rules. Import from shared modules instead.',
      },
    ],
  },
  qualityScoreTarget: 95,
};
