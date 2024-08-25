import * as fs from 'fs';
import * as path from 'path';

/////////////////////////////////////

const filePathTestMerklePath = path.resolve(__dirname, './artifacts/tests/testMerklePath.json');

fs.readFile(filePathTestMerklePath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading file:', err);
        return;
    }

    // Replace occurrences of "OP_2 OP_MUL" with "OP_DUP OP_ADD",
    // since BTC doesn't support OP_MUL...
    const result = data.replace(/5295/g, '7693');

    fs.writeFile(filePathTestMerklePath, result, 'utf8', (err) => {
        if (err) {
            console.error('Error writing file:', err);
            return;
        }

        console.log('Post-compile hook completed for:', filePathTestMerklePath.toString())
    });
});

/////////////////////////////////////

