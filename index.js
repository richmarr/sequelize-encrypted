var crypto = require('crypto');

function EncryptedField(Sequelize, key, opt) {
    if (!(this instanceof EncryptedField)) {
        return new EncryptedField(Sequelize, key, opt);
    }

    var self = this;
    self.key = new Buffer(key, 'hex');
    self.Sequelize = Sequelize;

    opt = opt || {};
    self._algorithm = opt.algorithm || 'aes-256-cbc';
    self._iv_length = opt.iv_length || 16;
    self._db_encoding = opt.db_encoding || 'binary';
};

EncryptedField.prototype.vault = function(name) {
    var self = this;

    return {
        type: self.Sequelize.BLOB,
        get: function() {
            var previous = this.getDataValue(name);
            if (!previous) {
                return {};
            }
            previous = new Buffer( previous, self._db_encoding );
            var iv = previous.slice(0, self._iv_length);
            var content = previous.slice(self._iv_length, previous.length);
            var decipher = crypto.createDecipheriv(self._algorithm, self.key, iv);

            var json = decipher.update(content, undefined, 'utf8') + decipher.final('utf8');
            return JSON.parse(json);
        },
        set: function(value) {
            // if new data is set, we will use a new IV
            var new_iv = crypto.randomBytes(self._iv_length);

            var cipher = crypto.createCipheriv(self._algorithm, self.key, new_iv);

            var enc_final = Buffer.concat([
                new_iv,
                cipher.update(JSON.stringify(value),'utf8'),
                cipher.final()
            ]);

            var previous = this.setDataValue( name, enc_final.toString(self._db_encoding) );
        }
    }
};

EncryptedField.prototype.field = function(name) {
    var self = this;

    return {
        type: self.Sequelize.VIRTUAL,
        set: function set_encrypted(val) {
            // use `this` not self because we need to reference the sequelize instance
            // not our EncryptedField instance
            var encrypted = this.encrypted;
            encrypted[name] = val;
            this.encrypted = encrypted;
        },
        get: function get_encrypted() {
            var encrypted = this.encrypted;
            return encrypted[name];
        }
    }
};

module.exports = EncryptedField;
