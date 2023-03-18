const fs        = require('fs');

const mds3 = require('./fido-mds3/index.js');
const mds3_client = new mds3.Builder().build();

//for test
/*mds3_client.findByAAGUID('9c835346-796b-4c27-8898-d6032f515cc5').then(data => {
  console.log(data);
});*/

if(process.env.FIDO_CONFORMANCE_TEST){
  try {
    mds3_client.judgeRefresh().then(data =>//load entries first.
      {
        const conformanceMetadataPath = './fido-conformance-metadata-statements';
        const conformanceMetadataFilenames = fs.readdirSync(conformanceMetadataPath);
        for (const statementPath of conformanceMetadataFilenames) {
          if (statementPath.endsWith('.json')) {
            const contents = fs.readFileSync(`${conformanceMetadataPath}/${statementPath}`, 'utf-8');
            mds3_client.append(JSON.parse(contents));
          }
        }
      }
    );
  } catch (err) {
    logger.warn('Failed to load fido-conformance-metadata-statements.' + err.message)
  }
}

module.exports.mds3_client = mds3_client;
