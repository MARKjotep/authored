//

interface obj<T> {
  [Key: string]: T;
}

interface fs {
  [key: string]: string | undefined | boolean | number;
}
interface bs {
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}
interface sesh_db {
  sid: string;
  data: string;
  expiration: string;
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}
