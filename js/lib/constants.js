class Grep11Constants {
  constructor(constants) {
    Object.entries(constants).forEach(([constant, value]) => {
      this[constant] = value;
    });
  }

  getName(value) {
    value = this.findValue(value);
    return value && value.name;
  }

  getValue(name) {
    let match = Object.entries(this).find(([c]) => c == name),
        [,value] = match || [];
    return value;
  }

  findValue(value) {
    let match = Object.entries(this).find(([,v]) => v == value),
        [name] = match || [];
    return name && { name, value: this[name] };
  }
}

exports.Grep11Constants = Grep11Constants;

