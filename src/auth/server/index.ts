import { oAss, obj, oLen } from "../../@";

class callBack {
  [Key: string]: any;
  data: obj<string>;
  modified: boolean;
  new: boolean = true;
  length = 0;
  constructor(initial: obj<string> = {}) {
    this.modified = true;
    this.data = {};
    this.length = oLen(initial);
    if (this.length) {
      this.new = false;
    }
    oAss(this.data, initial);
  }
  set(target: any, prop: string, val: string) {
    if (!this.readonly && target.data[prop] != val) {
      this.modified = true;
      if (!(prop in target.data)) {
        this.length++;
      }
      target.data[prop] = val;
      return true;
    }
    return false;
  }
  get(target: any, prop: string) {
    if (prop in target) {
      return target[prop];
    }
    return target.data[prop];
  }
  has(target: any, prop: string) {
    if (prop in target.data) {
      return true;
    }
    return false;
  }
  deleteProperty(target: any, val: string) {
    if (!this.readonly && val in target.data) {
      this.modified = true;
      delete target.data[val];
      this.length--;
    }
    return true;
  }
}

export class ServerSide extends callBack {
  [Key: string]: any;
  modified: boolean;
  private readonly readOnly: boolean;
  constructor(
    public sid: string = "",
    initial: obj<string> = {},
    readonly = false,
  ) {
    super(initial);
    this.modified = false;
    this.readOnly = readonly;
  }
  get session() {
    return new Proxy<ServerSide>(this, this);
  }
}
