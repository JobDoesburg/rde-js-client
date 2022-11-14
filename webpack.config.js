const path = require('path');

module.exports = {
    entry: {
        RDEKeyGen: './src/keygen.ts',
        RDEDecryption: './src/decryption.ts'
    },
    mode: 'development',
    watch: true,
    output: {
        filename: '[name].js',
        library: '[name]',
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
