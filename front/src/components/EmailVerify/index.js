import { useEffect, useState, Fragment } from "react";
import { useParams, Link } from "react-router-dom";
import axios from "axios";
import success_img from "../../images/success.png";
import styles from "./styles.module.css";

const EmailVerify = () => {
  const [validUrl, setValidUrl] = useState(true);
  const { id, token } = useParams();

  useEffect(() => {
    const verifyEmailUrl = async () => {
      try {
        const url = `http://localhost:1337/api/users/${id}/verify/${token}`;
        const response = await axios.get(url);
        console.log(response.data);
        setValidUrl(true);
      } catch (error) {
        console.log(error);
        setValidUrl(false);
      }
    };
    verifyEmailUrl();
  }, [id, token]);

  return (
    <Fragment>
      {validUrl ? (
        <div className={styles.container}>
          <img src={success_img} alt="success_img" className={styles.success_img} />
          <h1>Email verified successfully</h1>
          <Link to="/login">
            <button className={styles.green_btn}>Login</button>
          </Link>
        </div>
      ) : (
        <h1>404 Not Found</h1>
      )}
    </Fragment>
  );
};

export default EmailVerify;
