const path = require('path');

module.exports = {
    entry: './src/index.ts',
    mode: 'development',
    watch: true,
    output: {
        filename: 'RDEKeyGen.js',
        path: path.resolve(__dirname, 'dist'),
        library: 'RDEKeyGen',
    },
    module: {
        rules: [
            {
                test: /\.ts?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },

    resolve: {
        extensions: ['.ts', '.js'],
    },
};
