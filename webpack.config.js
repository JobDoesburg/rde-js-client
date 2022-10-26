const path = require('path');

module.exports = {
    entry: './src/index.js',
    mode: 'development',
    watch: true,
    output: {
        filename: 'rde-keygen.js',
        path: path.resolve(__dirname, 'dist'),
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
